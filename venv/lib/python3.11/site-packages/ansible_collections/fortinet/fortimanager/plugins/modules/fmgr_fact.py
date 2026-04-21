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
module: fmgr_fact
short_description: Gather fortimanager facts.
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
        description: The maximum time in seconds to wait for other user to release the workspace lock.
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
    facts:
        description: Gathering fortimanager facts.
        type: dict
        required: true
        suboptions:
            selector:
                required: true
                description: Selector of the retrieved fortimanager facts.
                type: str
                choices:
                    - 'adom_options'
                    - 'antivirus_mmschecksum'
                    - 'antivirus_mmschecksum_entries'
                    - 'antivirus_notification'
                    - 'antivirus_notification_entries'
                    - 'antivirus_profile'
                    - 'antivirus_profile_cifs'
                    - 'antivirus_profile_contentdisarm'
                    - 'antivirus_profile_ftp'
                    - 'antivirus_profile_http'
                    - 'antivirus_profile_imap'
                    - 'antivirus_profile_mapi'
                    - 'antivirus_profile_nacquar'
                    - 'antivirus_profile_nntp'
                    - 'antivirus_profile_outbreakprevention'
                    - 'antivirus_profile_pop3'
                    - 'antivirus_profile_smb'
                    - 'antivirus_profile_smtp'
                    - 'antivirus_profile_ssh'
                    - 'apcfgprofile'
                    - 'apcfgprofile_commandlist'
                    - 'application_casi_profile'
                    - 'application_casi_profile_entries'
                    - 'application_categories'
                    - 'application_custom'
                    - 'application_group'
                    - 'application_internetservice'
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
                    - 'casb_useractivity_match_tenantextraction'
                    - 'casb_useractivity_match_tenantextraction_filters'
                    - 'certificate_template'
                    - 'cifs_domaincontroller'
                    - 'cifs_profile'
                    - 'cifs_profile_filefilter'
                    - 'cifs_profile_filefilter_entries'
                    - 'cifs_profile_serverkeytab'
                    - 'cloud_orchestaws'
                    - 'cloud_orchestawsconnector'
                    - 'cloud_orchestawstemplate_autoscaleexistingvpc'
                    - 'cloud_orchestawstemplate_autoscalenewvpc'
                    - 'cloud_orchestawstemplate_autoscaletgwnewvpc'
                    - 'cloud_orchestration'
                    - 'credentialstore_domaincontroller'
                    - 'devprof_device_profile_fortianalyzer'
                    - 'devprof_device_profile_fortiguard'
                    - 'devprof_log_fortianalyzer_setting'
                    - 'devprof_log_fortianalyzercloud_setting'
                    - 'devprof_log_syslogd_filter'
                    - 'devprof_log_syslogd_filter_excludelist'
                    - 'devprof_log_syslogd_filter_excludelist_fields'
                    - 'devprof_log_syslogd_filter_freestyle'
                    - 'devprof_log_syslogd_setting'
                    - 'devprof_log_syslogd_setting_customfieldname'
                    - 'devprof_system_centralmanagement'
                    - 'devprof_system_centralmanagement_serverlist'
                    - 'devprof_system_dns'
                    - 'devprof_system_emailserver'
                    - 'devprof_system_global'
                    - 'devprof_system_ntp'
                    - 'devprof_system_ntp_ntpserver'
                    - 'devprof_system_replacemsg_admin'
                    - 'devprof_system_replacemsg_alertmail'
                    - 'devprof_system_replacemsg_auth'
                    - 'devprof_system_replacemsg_devicedetectionportal'
                    - 'devprof_system_replacemsg_ec'
                    - 'devprof_system_replacemsg_fortiguardwf'
                    - 'devprof_system_replacemsg_ftp'
                    - 'devprof_system_replacemsg_http'
                    - 'devprof_system_replacemsg_mail'
                    - 'devprof_system_replacemsg_mms'
                    - 'devprof_system_replacemsg_nacquar'
                    - 'devprof_system_replacemsg_nntp'
                    - 'devprof_system_replacemsg_spam'
                    - 'devprof_system_replacemsg_sslvpn'
                    - 'devprof_system_replacemsg_trafficquota'
                    - 'devprof_system_replacemsg_utm'
                    - 'devprof_system_replacemsg_webproxy'
                    - 'devprof_system_snmp_community'
                    - 'devprof_system_snmp_community_hosts'
                    - 'devprof_system_snmp_community_hosts6'
                    - 'devprof_system_snmp_sysinfo'
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
                    - 'dnsfilter_profile_domainfilter'
                    - 'dnsfilter_profile_ftgddns'
                    - 'dnsfilter_profile_ftgddns_filters'
                    - 'dnsfilter_profile_urlfilter'
                    - 'dnsfilter_urlfilter'
                    - 'dnsfilter_urlfilter_entries'
                    - 'dvmdb_adom'
                    - 'dvmdb_device'
                    - 'dvmdb_device_haslave'
                    - 'dvmdb_device_vdom'
                    - 'dvmdb_folder'
                    - 'dvmdb_group'
                    - 'dvmdb_metafields_adom'
                    - 'dvmdb_metafields_device'
                    - 'dvmdb_metafields_group'
                    - 'dvmdb_revision'
                    - 'dvmdb_script'
                    - 'dvmdb_script_log_latest'
                    - 'dvmdb_script_log_latest_device'
                    - 'dvmdb_script_log_list'
                    - 'dvmdb_script_log_list_device'
                    - 'dvmdb_script_log_output_device_logid'
                    - 'dvmdb_script_log_output_logid'
                    - 'dvmdb_script_log_summary'
                    - 'dvmdb_script_log_summary_device'
                    - 'dvmdb_script_scriptschedule'
                    - 'dvmdb_workflow'
                    - 'dvmdb_workflow_wflog'
                    - 'dvmdb_workspace_dirty'
                    - 'dvmdb_workspace_dirty_dev'
                    - 'dvmdb_workspace_lockinfo'
                    - 'dvmdb_workspace_lockinfo_dev'
                    - 'dvmdb_workspace_lockinfo_obj'
                    - 'dvmdb_workspace_lockinfo_pkg'
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
                    - 'emailfilter_fortishield'
                    - 'emailfilter_iptrust'
                    - 'emailfilter_iptrust_entries'
                    - 'emailfilter_mheader'
                    - 'emailfilter_mheader_entries'
                    - 'emailfilter_options'
                    - 'emailfilter_profile'
                    - 'emailfilter_profile_filefilter'
                    - 'emailfilter_profile_filefilter_entries'
                    - 'emailfilter_profile_gmail'
                    - 'emailfilter_profile_imap'
                    - 'emailfilter_profile_mapi'
                    - 'emailfilter_profile_msnhotmail'
                    - 'emailfilter_profile_otherwebmails'
                    - 'emailfilter_profile_pop3'
                    - 'emailfilter_profile_smtp'
                    - 'emailfilter_profile_yahoomail'
                    - 'endpointcontrol_fctems'
                    - 'extendercontroller_dataplan'
                    - 'extendercontroller_extenderprofile'
                    - 'extendercontroller_extenderprofile_cellular'
                    - 'extendercontroller_extenderprofile_cellular_controllerreport'
                    - 'extendercontroller_extenderprofile_cellular_modem1'
                    - 'extendercontroller_extenderprofile_cellular_modem1_autoswitch'
                    - 'extendercontroller_extenderprofile_cellular_modem2'
                    - 'extendercontroller_extenderprofile_cellular_modem2_autoswitch'
                    - 'extendercontroller_extenderprofile_cellular_smsnotification'
                    - 'extendercontroller_extenderprofile_cellular_smsnotification_alert'
                    - 'extendercontroller_extenderprofile_cellular_smsnotification_receiver'
                    - 'extendercontroller_extenderprofile_lanextension'
                    - 'extendercontroller_extenderprofile_lanextension_backhaul'
                    - 'extendercontroller_simprofile'
                    - 'extendercontroller_simprofile_autoswitchprofile'
                    - 'extendercontroller_template'
                    - 'extensioncontroller_dataplan'
                    - 'extensioncontroller_extenderprofile'
                    - 'extensioncontroller_extenderprofile_cellular'
                    - 'extensioncontroller_extenderprofile_cellular_controllerreport'
                    - 'extensioncontroller_extenderprofile_cellular_modem1'
                    - 'extensioncontroller_extenderprofile_cellular_modem1_autoswitch'
                    - 'extensioncontroller_extenderprofile_cellular_modem2'
                    - 'extensioncontroller_extenderprofile_cellular_modem2_autoswitch'
                    - 'extensioncontroller_extenderprofile_cellular_smsnotification'
                    - 'extensioncontroller_extenderprofile_cellular_smsnotification_alert'
                    - 'extensioncontroller_extenderprofile_cellular_smsnotification_receiver'
                    - 'extensioncontroller_extenderprofile_lanextension'
                    - 'extensioncontroller_extenderprofile_lanextension_backhaul'
                    - 'extensioncontroller_extenderprofile_lanextension_trafficsplitservices'
                    - 'extensioncontroller_extenderprofile_wifi'
                    - 'extensioncontroller_extenderprofile_wifi_radio1'
                    - 'extensioncontroller_extenderprofile_wifi_radio2'
                    - 'extensioncontroller_extendervap'
                    - 'filefilter_profile'
                    - 'filefilter_profile_rules'
                    - 'firewall_accessproxy'
                    - 'firewall_accessproxy6'
                    - 'firewall_accessproxy6_apigateway'
                    - 'firewall_accessproxy6_apigateway6'
                    - 'firewall_accessproxy6_apigateway6_quic'
                    - 'firewall_accessproxy6_apigateway6_realservers'
                    - 'firewall_accessproxy6_apigateway6_sslciphersuites'
                    - 'firewall_accessproxy6_apigateway_quic'
                    - 'firewall_accessproxy6_apigateway_realservers'
                    - 'firewall_accessproxy6_apigateway_sslciphersuites'
                    - 'firewall_accessproxy_apigateway'
                    - 'firewall_accessproxy_apigateway6'
                    - 'firewall_accessproxy_apigateway6_quic'
                    - 'firewall_accessproxy_apigateway6_realservers'
                    - 'firewall_accessproxy_apigateway6_sslciphersuites'
                    - 'firewall_accessproxy_apigateway_quic'
                    - 'firewall_accessproxy_apigateway_realservers'
                    - 'firewall_accessproxy_apigateway_sslciphersuites'
                    - 'firewall_accessproxy_realservers'
                    - 'firewall_accessproxy_serverpubkeyauthsettings'
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
                    - 'firewall_gtp_ievalidation'
                    - 'firewall_gtp_imsi'
                    - 'firewall_gtp_ippolicy'
                    - 'firewall_gtp_messagefilter'
                    - 'firewall_gtp_messageratelimit'
                    - 'firewall_gtp_messageratelimitv0'
                    - 'firewall_gtp_messageratelimitv1'
                    - 'firewall_gtp_messageratelimitv2'
                    - 'firewall_gtp_noippolicy'
                    - 'firewall_gtp_perapnshaper'
                    - 'firewall_gtp_policy'
                    - 'firewall_gtp_policyv2'
                    - 'firewall_identitybasedroute'
                    - 'firewall_identitybasedroute_rule'
                    - 'firewall_internetservice'
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
                    - 'firewall_mmsprofile_dupe'
                    - 'firewall_mmsprofile_flood'
                    - 'firewall_mmsprofile_notification'
                    - 'firewall_mmsprofile_notifmsisdn'
                    - 'firewall_mmsprofile_outbreakprevention'
                    - 'firewall_multicastaddress'
                    - 'firewall_multicastaddress6'
                    - 'firewall_multicastaddress6_tagging'
                    - 'firewall_multicastaddress_tagging'
                    - 'firewall_networkservicedynamic'
                    - 'firewall_profilegroup'
                    - 'firewall_profileprotocoloptions'
                    - 'firewall_profileprotocoloptions_cifs'
                    - 'firewall_profileprotocoloptions_cifs_filefilter'
                    - 'firewall_profileprotocoloptions_cifs_filefilter_entries'
                    - 'firewall_profileprotocoloptions_cifs_serverkeytab'
                    - 'firewall_profileprotocoloptions_dns'
                    - 'firewall_profileprotocoloptions_ftp'
                    - 'firewall_profileprotocoloptions_http'
                    - 'firewall_profileprotocoloptions_imap'
                    - 'firewall_profileprotocoloptions_mailsignature'
                    - 'firewall_profileprotocoloptions_mapi'
                    - 'firewall_profileprotocoloptions_nntp'
                    - 'firewall_profileprotocoloptions_pop3'
                    - 'firewall_profileprotocoloptions_smtp'
                    - 'firewall_profileprotocoloptions_ssh'
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
                    - 'firewall_sslsshprofile_dot'
                    - 'firewall_sslsshprofile_echoutersni'
                    - 'firewall_sslsshprofile_ftps'
                    - 'firewall_sslsshprofile_https'
                    - 'firewall_sslsshprofile_imaps'
                    - 'firewall_sslsshprofile_pop3s'
                    - 'firewall_sslsshprofile_smtps'
                    - 'firewall_sslsshprofile_ssh'
                    - 'firewall_sslsshprofile_ssl'
                    - 'firewall_sslsshprofile_sslexempt'
                    - 'firewall_sslsshprofile_sslserver'
                    - 'firewall_trafficclass'
                    - 'firewall_vendormac'
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
                    - 'firewall_vip6_quic'
                    - 'firewall_vip6_realservers'
                    - 'firewall_vip6_sslciphersuites'
                    - 'firewall_vip6_sslserverciphersuites'
                    - 'firewall_vip_dynamicmapping'
                    - 'firewall_vip_dynamicmapping_realservers'
                    - 'firewall_vip_dynamicmapping_sslciphersuites'
                    - 'firewall_vip_gslbpublicips'
                    - 'firewall_vip_quic'
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
                    - 'fmg_sasemanager_settings'
                    - 'fmg_sasemanager_status'
                    - 'fmg_variable'
                    - 'fmg_variable_dynamicmapping'
                    - 'fmupdate_analyzer_virusreport'
                    - 'fmupdate_avips_advancedlog'
                    - 'fmupdate_avips_webproxy'
                    - 'fmupdate_customurllist'
                    - 'fmupdate_diskquota'
                    - 'fmupdate_fctservices'
                    - 'fmupdate_fdssetting'
                    - 'fmupdate_fdssetting_pushoverride'
                    - 'fmupdate_fdssetting_pushoverridetoclient'
                    - 'fmupdate_fdssetting_pushoverridetoclient_announceip'
                    - 'fmupdate_fdssetting_serveroverride'
                    - 'fmupdate_fdssetting_serveroverride_servlist'
                    - 'fmupdate_fdssetting_updateschedule'
                    - 'fmupdate_fgdsetting'
                    - 'fmupdate_fgdsetting_serveroverride'
                    - 'fmupdate_fgdsetting_serveroverride_servlist'
                    - 'fmupdate_fwmsetting'
                    - 'fmupdate_fwmsetting_upgradetimeout'
                    - 'fmupdate_multilayer'
                    - 'fmupdate_publicnetwork'
                    - 'fmupdate_serveraccesspriorities'
                    - 'fmupdate_serveraccesspriorities_privateserver'
                    - 'fmupdate_serveroverridestatus'
                    - 'fmupdate_service'
                    - 'fmupdate_webspam_fgdsetting'
                    - 'fmupdate_webspam_fgdsetting_serveroverride'
                    - 'fmupdate_webspam_fgdsetting_serveroverride_servlist'
                    - 'fmupdate_webspam_webproxy'
                    - 'footer_consolidated_policy'
                    - 'footer_policy'
                    - 'footer_policy6'
                    - 'footer_policy6_identitybasedpolicy6'
                    - 'footer_policy_identitybasedpolicy'
                    - 'footer_shapingpolicy'
                    - 'fsp_vlan'
                    - 'fsp_vlan_dhcpserver'
                    - 'fsp_vlan_dhcpserver_excluderange'
                    - 'fsp_vlan_dhcpserver_iprange'
                    - 'fsp_vlan_dhcpserver_options'
                    - 'fsp_vlan_dhcpserver_reservedaddress'
                    - 'fsp_vlan_dynamicmapping'
                    - 'fsp_vlan_dynamicmapping_dhcpserver'
                    - 'fsp_vlan_dynamicmapping_dhcpserver_excluderange'
                    - 'fsp_vlan_dynamicmapping_dhcpserver_iprange'
                    - 'fsp_vlan_dynamicmapping_dhcpserver_options'
                    - 'fsp_vlan_dynamicmapping_dhcpserver_reservedaddress'
                    - 'fsp_vlan_dynamicmapping_interface'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6_ip6extraaddr'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6_ip6prefixlist'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6_vrrp6'
                    - 'fsp_vlan_dynamicmapping_interface_secondaryip'
                    - 'fsp_vlan_dynamicmapping_interface_vrrp'
                    - 'fsp_vlan_dynamicmapping_interface_vrrp_proxyarp'
                    - 'fsp_vlan_interface'
                    - 'fsp_vlan_interface_ipv6'
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
                    - 'header_consolidated_policy'
                    - 'header_policy'
                    - 'header_policy6'
                    - 'header_policy6_identitybasedpolicy6'
                    - 'header_policy_identitybasedpolicy'
                    - 'header_shapingpolicy'
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
                    - 'log_npuserver'
                    - 'log_npuserver_servergroup'
                    - 'log_npuserver_serverinfo'
                    - 'metafields_system_admin_user'
                    - 'mpskprofile'
                    - 'mpskprofile_mpskgroup'
                    - 'mpskprofile_mpskgroup_mpskkey'
                    - 'nacprofile'
                    - 'pkg_authentication_rule'
                    - 'pkg_authentication_setting'
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
                    - 'pm_config_adom_options'
                    - 'pm_config_application_list'
                    - 'pm_config_category_list'
                    - 'pm_config_data_defaultsslvpnoschecklist'
                    - 'pm_config_data_tablesize'
                    - 'pm_config_data_tablesize_faz'
                    - 'pm_config_data_tablesize_fmg'
                    - 'pm_config_data_tablesize_fos'
                    - 'pm_config_data_tablesize_log'
                    - 'pm_config_fct_endpointcontrol_profile'
                    - 'pm_config_metafields_firewall_address'
                    - 'pm_config_metafields_firewall_addrgrp'
                    - 'pm_config_metafields_firewall_centralsnatmap'
                    - 'pm_config_metafields_firewall_policy'
                    - 'pm_config_metafields_firewall_service_custom'
                    - 'pm_config_metafields_firewall_service_group'
                    - 'pm_config_package_status'
                    - 'pm_config_pblock_firewall_consolidated_policy'
                    - 'pm_config_pblock_firewall_policy'
                    - 'pm_config_pblock_firewall_policy6'
                    - 'pm_config_pblock_firewall_proxypolicy'
                    - 'pm_config_pblock_firewall_securitypolicy'
                    - 'pm_config_rule_list'
                    - 'pm_devprof'
                    - 'pm_devprof_adom'
                    - 'pm_pblock'
                    - 'pm_pblock_adom'
                    - 'pm_pkg'
                    - 'pm_pkg_adom'
                    - 'pm_pkg_global'
                    - 'pm_pkg_schedule'
                    - 'pm_wanprof'
                    - 'pm_wanprof_adom'
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
                    - 'spamfilter_profile_gmail'
                    - 'spamfilter_profile_imap'
                    - 'spamfilter_profile_mapi'
                    - 'spamfilter_profile_msnhotmail'
                    - 'spamfilter_profile_pop3'
                    - 'spamfilter_profile_smtp'
                    - 'spamfilter_profile_yahoomail'
                    - 'sshfilter_profile'
                    - 'sshfilter_profile_filefilter'
                    - 'sshfilter_profile_filefilter_entries'
                    - 'sshfilter_profile_shellcommands'
                    - 'switchcontroller_acl_group'
                    - 'switchcontroller_acl_ingress'
                    - 'switchcontroller_acl_ingress_action'
                    - 'switchcontroller_acl_ingress_classifier'
                    - 'switchcontroller_customcommand'
                    - 'switchcontroller_dsl_policy'
                    - 'switchcontroller_dynamicportpolicy'
                    - 'switchcontroller_dynamicportpolicy_policy'
                    - 'switchcontroller_fortilinksettings'
                    - 'switchcontroller_fortilinksettings_nacports'
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
                    - 'switchcontroller_managedswitch_snmpsysinfo'
                    - 'switchcontroller_managedswitch_snmptrapthreshold'
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
                    - 'sys_ha_status'
                    - 'sys_status'
                    - 'system_admin_group'
                    - 'system_admin_group_member'
                    - 'system_admin_ldap'
                    - 'system_admin_ldap_adom'
                    - 'system_admin_profile'
                    - 'system_admin_profile_datamaskcustomfields'
                    - 'system_admin_profile_writepasswdprofiles'
                    - 'system_admin_profile_writepasswduserlist'
                    - 'system_admin_radius'
                    - 'system_admin_setting'
                    - 'system_admin_tacacs'
                    - 'system_admin_user'
                    - 'system_admin_user_adom'
                    - 'system_admin_user_adomexclude'
                    - 'system_admin_user_appfilter'
                    - 'system_admin_user_dashboard'
                    - 'system_admin_user_dashboardtabs'
                    - 'system_admin_user_ipsfilter'
                    - 'system_admin_user_metadata'
                    - 'system_admin_user_policyblock'
                    - 'system_admin_user_policypackage'
                    - 'system_admin_user_restrictdevvdom'
                    - 'system_admin_user_webfilter'
                    - 'system_alertconsole'
                    - 'system_alertemail'
                    - 'system_alertevent'
                    - 'system_alertevent_alertdestination'
                    - 'system_autodelete'
                    - 'system_autodelete_dlpfilesautodeletion'
                    - 'system_autodelete_logautodeletion'
                    - 'system_autodelete_quarantinefilesautodeletion'
                    - 'system_autodelete_reportautodeletion'
                    - 'system_backup_allsettings'
                    - 'system_certificate_ca'
                    - 'system_certificate_crl'
                    - 'system_certificate_local'
                    - 'system_certificate_oftp'
                    - 'system_certificate_remote'
                    - 'system_certificate_ssh'
                    - 'system_connector'
                    - 'system_csf'
                    - 'system_csf_fabricconnector'
                    - 'system_csf_trustedlist'
                    - 'system_customlanguage'
                    - 'system_dhcp_server'
                    - 'system_dhcp_server_excluderange'
                    - 'system_dhcp_server_iprange'
                    - 'system_dhcp_server_options'
                    - 'system_dhcp_server_reservedaddress'
                    - 'system_dm'
                    - 'system_dns'
                    - 'system_docker'
                    - 'system_externalresource'
                    - 'system_externalresource_dynamicmapping'
                    - 'system_fips'
                    - 'system_fmgcluster'
                    - 'system_fmgcluster_peer'
                    - 'system_fortiguard'
                    - 'system_fortiview_autocache'
                    - 'system_fortiview_setting'
                    - 'system_geoipcountry'
                    - 'system_geoipoverride'
                    - 'system_geoipoverride_ip6range'
                    - 'system_geoipoverride_iprange'
                    - 'system_global'
                    - 'system_guiact'
                    - 'system_ha'
                    - 'system_ha_monitoredinterfaces'
                    - 'system_ha_monitoredips'
                    - 'system_ha_peer'
                    - 'system_hascheduledcheck'
                    - 'system_interface'
                    - 'system_interface_ipv6'
                    - 'system_interface_member'
                    - 'system_localinpolicy'
                    - 'system_localinpolicy6'
                    - 'system_locallog_disk_filter'
                    - 'system_locallog_disk_setting'
                    - 'system_locallog_fortianalyzer2_filter'
                    - 'system_locallog_fortianalyzer2_setting'
                    - 'system_locallog_fortianalyzer3_filter'
                    - 'system_locallog_fortianalyzer3_setting'
                    - 'system_locallog_fortianalyzer_filter'
                    - 'system_locallog_fortianalyzer_setting'
                    - 'system_locallog_memory_filter'
                    - 'system_locallog_memory_setting'
                    - 'system_locallog_setting'
                    - 'system_locallog_syslogd2_filter'
                    - 'system_locallog_syslogd2_setting'
                    - 'system_locallog_syslogd3_filter'
                    - 'system_locallog_syslogd3_setting'
                    - 'system_locallog_syslogd_filter'
                    - 'system_locallog_syslogd_setting'
                    - 'system_log_alert'
                    - 'system_log_devicedisable'
                    - 'system_log_deviceselector'
                    - 'system_log_fospolicystats'
                    - 'system_log_interfacestats'
                    - 'system_log_ioc'
                    - 'system_log_maildomain'
                    - 'system_log_ratelimit'
                    - 'system_log_ratelimit_device'
                    - 'system_log_ratelimit_ratelimits'
                    - 'system_log_settings'
                    - 'system_log_settings_rollinganalyzer'
                    - 'system_log_settings_rollinglocal'
                    - 'system_log_settings_rollingregular'
                    - 'system_log_topology'
                    - 'system_log_ueba'
                    - 'system_logfetch_clientprofile'
                    - 'system_logfetch_clientprofile_devicefilter'
                    - 'system_logfetch_clientprofile_logfilter'
                    - 'system_logfetch_serversettings'
                    - 'system_mail'
                    - 'system_mcpolicydisabledadoms'
                    - 'system_meta'
                    - 'system_meta_sysmetafields'
                    - 'system_metadata_admins'
                    - 'system_npu'
                    - 'system_npu_backgroundssescan'
                    - 'system_npu_dosoptions'
                    - 'system_npu_dswdtsprofile'
                    - 'system_npu_dswqueuedtsprofile'
                    - 'system_npu_fpanomaly'
                    - 'system_npu_hpe'
                    - 'system_npu_icmpratectrl'
                    - 'system_npu_ipreassembly'
                    - 'system_npu_isfnpqueues'
                    - 'system_npu_npqueues'
                    - 'system_npu_npqueues_ethernettype'
                    - 'system_npu_npqueues_ipprotocol'
                    - 'system_npu_npqueues_ipservice'
                    - 'system_npu_npqueues_profile'
                    - 'system_npu_npqueues_scheduler'
                    - 'system_npu_nputcam'
                    - 'system_npu_nputcam_data'
                    - 'system_npu_nputcam_mask'
                    - 'system_npu_nputcam_miract'
                    - 'system_npu_nputcam_priact'
                    - 'system_npu_nputcam_sact'
                    - 'system_npu_nputcam_tact'
                    - 'system_npu_portcpumap'
                    - 'system_npu_portnpumap'
                    - 'system_npu_portpathoption'
                    - 'system_npu_priorityprotocol'
                    - 'system_npu_ssehascan'
                    - 'system_npu_swehhash'
                    - 'system_npu_swtrhash'
                    - 'system_npu_tcptimeoutprofile'
                    - 'system_npu_udptimeoutprofile'
                    - 'system_ntp'
                    - 'system_ntp_ntpserver'
                    - 'system_objecttag'
                    - 'system_objecttagging'
                    - 'system_passwordpolicy'
                    - 'system_performance'
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
                    - 'system_report_autocache'
                    - 'system_report_estbrowsetime'
                    - 'system_report_group'
                    - 'system_report_group_chartalternative'
                    - 'system_report_group_groupby'
                    - 'system_report_setting'
                    - 'system_route'
                    - 'system_route6'
                    - 'system_saml'
                    - 'system_saml_fabricidp'
                    - 'system_saml_serviceproviders'
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
                    - 'system_sniffer'
                    - 'system_snmp_community'
                    - 'system_snmp_community_hosts'
                    - 'system_snmp_community_hosts6'
                    - 'system_snmp_sysinfo'
                    - 'system_snmp_user'
                    - 'system_socfabric'
                    - 'system_socfabric_trustedlist'
                    - 'system_sql'
                    - 'system_sql_customindex'
                    - 'system_sql_customskipidx'
                    - 'system_sql_tsindexfield'
                    - 'system_sslciphersuites'
                    - 'system_status'
                    - 'system_syslog'
                    - 'system_virtualwirepair'
                    - 'system_webproxy'
                    - 'system_workflow_approvalmatrix'
                    - 'system_workflow_approvalmatrix_approver'
                    - 'task_task'
                    - 'task_task_history'
                    - 'task_task_line'
                    - 'task_task_line_history'
                    - 'telemetrycontroller_agentprofile'
                    - 'telemetrycontroller_application_predefine'
                    - 'telemetrycontroller_profile'
                    - 'telemetrycontroller_profile_application'
                    - 'telemetrycontroller_profile_application_sla'
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
                    - 'user_group_dynamicmapping_sslvpnoschecklist'
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
                    - 'vap_portalmessageoverrides'
                    - 'vap_vlanname'
                    - 'vap_vlanpool'
                    - 'vapgroup'
                    - 'videofilter_keyword'
                    - 'videofilter_keyword_word'
                    - 'videofilter_profile'
                    - 'videofilter_profile_filters'
                    - 'videofilter_profile_fortiguardcategory'
                    - 'videofilter_profile_fortiguardcategory_filters'
                    - 'videofilter_youtubechannelfilter'
                    - 'videofilter_youtubechannelfilter_entries'
                    - 'videofilter_youtubekey'
                    - 'virtualpatch_profile'
                    - 'virtualpatch_profile_exemption'
                    - 'voip_profile'
                    - 'voip_profile_msrp'
                    - 'voip_profile_sccp'
                    - 'voip_profile_sip'
                    - 'vpn_certificate_ca'
                    - 'vpn_certificate_ocspserver'
                    - 'vpn_certificate_remote'
                    - 'vpn_ipsec_fec'
                    - 'vpn_ipsec_fec_mappings'
                    - 'vpn_ssl_settings'
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
                    - 'vpnsslweb_portal_landingpage'
                    - 'vpnsslweb_portal_landingpage_formdata'
                    - 'vpnsslweb_portal_macaddrcheckrule'
                    - 'vpnsslweb_portal_oschecklist'
                    - 'vpnsslweb_portal_splitdns'
                    - 'vpnsslweb_realm'
                    - 'vpnsslweb_virtualdesktopapplist'
                    - 'vpnsslweb_virtualdesktopapplist_apps'
                    - 'waf_mainclass'
                    - 'waf_profile'
                    - 'waf_profile_addresslist'
                    - 'waf_profile_constraint'
                    - 'waf_profile_constraint_contentlength'
                    - 'waf_profile_constraint_exception'
                    - 'waf_profile_constraint_headerlength'
                    - 'waf_profile_constraint_hostname'
                    - 'waf_profile_constraint_linelength'
                    - 'waf_profile_constraint_malformed'
                    - 'waf_profile_constraint_maxcookie'
                    - 'waf_profile_constraint_maxheaderline'
                    - 'waf_profile_constraint_maxrangesegment'
                    - 'waf_profile_constraint_maxurlparam'
                    - 'waf_profile_constraint_method'
                    - 'waf_profile_constraint_paramlength'
                    - 'waf_profile_constraint_urlparamlength'
                    - 'waf_profile_constraint_version'
                    - 'waf_profile_method'
                    - 'waf_profile_method_methodpolicy'
                    - 'waf_profile_signature'
                    - 'waf_profile_signature_customsignature'
                    - 'waf_profile_signature_mainclass'
                    - 'waf_profile_urlaccess'
                    - 'waf_profile_urlaccess_accesspattern'
                    - 'waf_signature'
                    - 'waf_subclass'
                    - 'wagprofile'
                    - 'wanopt_authgroup'
                    - 'wanopt_peer'
                    - 'wanopt_profile'
                    - 'wanopt_profile_cifs'
                    - 'wanopt_profile_ftp'
                    - 'wanopt_profile_http'
                    - 'wanopt_profile_mapi'
                    - 'wanopt_profile_tcp'
                    - 'wanprof_system_sdwan'
                    - 'wanprof_system_sdwan_duplication'
                    - 'wanprof_system_sdwan_healthcheck'
                    - 'wanprof_system_sdwan_healthcheck_sla'
                    - 'wanprof_system_sdwan_members'
                    - 'wanprof_system_sdwan_neighbor'
                    - 'wanprof_system_sdwan_service'
                    - 'wanprof_system_sdwan_service_sla'
                    - 'wanprof_system_sdwan_zone'
                    - 'wanprof_system_virtualwanlink'
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
                    - 'webfilter_profile_antiphish'
                    - 'webfilter_profile_antiphish_custompatterns'
                    - 'webfilter_profile_antiphish_inspectionentries'
                    - 'webfilter_profile_filefilter'
                    - 'webfilter_profile_filefilter_entries'
                    - 'webfilter_profile_ftgdwf'
                    - 'webfilter_profile_ftgdwf_filters'
                    - 'webfilter_profile_ftgdwf_quota'
                    - 'webfilter_profile_ftgdwf_risk'
                    - 'webfilter_profile_override'
                    - 'webfilter_profile_urlextraction'
                    - 'webfilter_profile_web'
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
                    - 'wtpprofile_eslsesdongle'
                    - 'wtpprofile_lan'
                    - 'wtpprofile_lbs'
                    - 'wtpprofile_platform'
                    - 'wtpprofile_radio1'
                    - 'wtpprofile_radio2'
                    - 'wtpprofile_radio3'
                    - 'wtpprofile_radio4'
                    - 'wtpprofile_splittunnelingacl'
            fields:
                required: false
                description:
                    - Limit the output by returning only the attributes specified in the string array.
                    - If none specified, all attributes will be returned.
                type: list
                elements: raw
            filter:
                required: false
                description: Filter the result according to a set of criteria.
                type: list
                elements: raw
            option:
                required: false
                description:
                    - Set fetch option for the request. If no option is specified, by default the attributes of the objects will be returned.
                    - See more details in FNDN API documents.
                type: raw
            sortings:
                required: false
                description: Sorting rules list. Items are returned in ascending(1) or descending(-1) order of fields in the list.
                type: list
                elements: raw
            params:
                required: false
                description: The specific parameters for each different selector.
                type: dict
            extra_params:
                required: false
                description: Extra parameters for each different selector.
                type: dict
'''

EXAMPLES = '''
- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the scripts
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "dvmdb_script"
          params:
            adom: "root"
            script: ""

    - name: Retrive all the interfaces
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_interface"
          params:
            interface: ""
    - name: Retrieve the interface port1
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_interface"
          params:
            interface: "port1"
    - name: Fetch urlfilter with name urlfilter4
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "webfilter_urlfilter"
          params:
            adom: "root"
            urlfilter: ""
          filter:
            - - "name"
              - "=="
              - "urlfilter4"
          fields:
            - "id"
            - "name"
            - "comment"
          # option: "object member" # "count", "object member" or "syntax"
          sortings:
            - "id": 1
              "name": -1
    - name: Retrieve device
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "dvmdb_device"
          params:
            adom: "root"
            device: ""
          option:
            - "get meta"
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
    facts_metadata = {
        'adom_options': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/adom/options',
                '/pm/config/global/obj/adom/options'
            ]
        },
        'antivirus_mmschecksum': {
            'params': ['adom', 'mms-checksum'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/mms-checksum',
                '/pm/config/adom/{adom}/obj/antivirus/mms-checksum/{mms-checksum}',
                '/pm/config/global/obj/antivirus/mms-checksum',
                '/pm/config/global/obj/antivirus/mms-checksum/{mms-checksum}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'antivirus_mmschecksum_entries': {
            'params': ['adom', 'entries', 'mms-checksum'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/mms-checksum/{mms-checksum}/entries',
                '/pm/config/adom/{adom}/obj/antivirus/mms-checksum/{mms-checksum}/entries/{entries}',
                '/pm/config/global/obj/antivirus/mms-checksum/{mms-checksum}/entries',
                '/pm/config/global/obj/antivirus/mms-checksum/{mms-checksum}/entries/{entries}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'antivirus_notification': {
            'params': ['adom', 'notification'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/notification',
                '/pm/config/adom/{adom}/obj/antivirus/notification/{notification}',
                '/pm/config/global/obj/antivirus/notification',
                '/pm/config/global/obj/antivirus/notification/{notification}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'antivirus_notification_entries': {
            'params': ['adom', 'entries', 'notification'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/notification/{notification}/entries',
                '/pm/config/adom/{adom}/obj/antivirus/notification/{notification}/entries/{entries}',
                '/pm/config/global/obj/antivirus/notification/{notification}/entries',
                '/pm/config/global/obj/antivirus/notification/{notification}/entries/{entries}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'antivirus_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile',
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}',
                '/pm/config/global/obj/antivirus/profile',
                '/pm/config/global/obj/antivirus/profile/{profile}'
            ]
        },
        'antivirus_profile_cifs': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/cifs',
                '/pm/config/global/obj/antivirus/profile/{profile}/cifs'
            ],
            'v_range': [['6.2.0', '']]
        },
        'antivirus_profile_contentdisarm': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/content-disarm',
                '/pm/config/global/obj/antivirus/profile/{profile}/content-disarm'
            ]
        },
        'antivirus_profile_ftp': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/ftp',
                '/pm/config/global/obj/antivirus/profile/{profile}/ftp'
            ]
        },
        'antivirus_profile_http': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/http',
                '/pm/config/global/obj/antivirus/profile/{profile}/http'
            ]
        },
        'antivirus_profile_imap': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/imap',
                '/pm/config/global/obj/antivirus/profile/{profile}/imap'
            ]
        },
        'antivirus_profile_mapi': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/mapi',
                '/pm/config/global/obj/antivirus/profile/{profile}/mapi'
            ]
        },
        'antivirus_profile_nacquar': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/nac-quar',
                '/pm/config/global/obj/antivirus/profile/{profile}/nac-quar'
            ]
        },
        'antivirus_profile_nntp': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/nntp',
                '/pm/config/global/obj/antivirus/profile/{profile}/nntp'
            ]
        },
        'antivirus_profile_outbreakprevention': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/outbreak-prevention',
                '/pm/config/global/obj/antivirus/profile/{profile}/outbreak-prevention'
            ],
            'v_range': [['6.2.0', '']]
        },
        'antivirus_profile_pop3': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/pop3',
                '/pm/config/global/obj/antivirus/profile/{profile}/pop3'
            ]
        },
        'antivirus_profile_smb': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/smb',
                '/pm/config/global/obj/antivirus/profile/{profile}/smb'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'antivirus_profile_smtp': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/smtp',
                '/pm/config/global/obj/antivirus/profile/{profile}/smtp'
            ]
        },
        'antivirus_profile_ssh': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}/ssh',
                '/pm/config/global/obj/antivirus/profile/{profile}/ssh'
            ],
            'v_range': [['6.2.2', '']]
        },
        'apcfgprofile': {
            'params': ['adom', 'apcfg-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile/{apcfg-profile}',
                '/pm/config/global/obj/wireless-controller/apcfg-profile',
                '/pm/config/global/obj/wireless-controller/apcfg-profile/{apcfg-profile}'
            ],
            'v_range': [['6.4.6', '']]
        },
        'apcfgprofile_commandlist': {
            'params': ['adom', 'apcfg-profile', 'command-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}',
                '/pm/config/global/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list',
                '/pm/config/global/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}'
            ],
            'v_range': [['6.4.6', '']]
        },
        'application_casi_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/casi/profile',
                '/pm/config/adom/{adom}/obj/application/casi/profile/{profile}',
                '/pm/config/global/obj/application/casi/profile',
                '/pm/config/global/obj/application/casi/profile/{profile}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'application_casi_profile_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/casi/profile/{profile}/entries',
                '/pm/config/adom/{adom}/obj/application/casi/profile/{profile}/entries/{entries}',
                '/pm/config/global/obj/application/casi/profile/{profile}/entries',
                '/pm/config/global/obj/application/casi/profile/{profile}/entries/{entries}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'application_categories': {
            'params': ['adom', 'categories'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/categories',
                '/pm/config/adom/{adom}/obj/application/categories/{categories}',
                '/pm/config/global/obj/application/categories',
                '/pm/config/global/obj/application/categories/{categories}'
            ]
        },
        'application_custom': {
            'params': ['adom', 'custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/custom',
                '/pm/config/adom/{adom}/obj/application/custom/{custom}',
                '/pm/config/global/obj/application/custom',
                '/pm/config/global/obj/application/custom/{custom}'
            ]
        },
        'application_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/group',
                '/pm/config/adom/{adom}/obj/application/group/{group}',
                '/pm/config/global/obj/application/group',
                '/pm/config/global/obj/application/group/{group}'
            ]
        },
        'application_internetservice': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service',
                '/pm/config/global/obj/application/internet-service'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'application_internetservice_entry': {
            'params': ['adom', 'entry'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service/entry',
                '/pm/config/adom/{adom}/obj/application/internet-service/entry/{entry}',
                '/pm/config/global/obj/application/internet-service/entry',
                '/pm/config/global/obj/application/internet-service/entry/{entry}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'application_internetservicecustom': {
            'params': ['adom', 'internet-service-custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service-custom',
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}',
                '/pm/config/global/obj/application/internet-service-custom',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'application_internetservicecustom_disableentry': {
            'params': ['adom', 'disable-entry', 'internet-service-custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/disable-entry',
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/disable-entry',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'application_internetservicecustom_disableentry_iprange': {
            'params': ['adom', 'disable-entry', 'internet-service-custom', 'ip-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range',
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'application_internetservicecustom_entry': {
            'params': ['adom', 'entry', 'internet-service-custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/entry',
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/entry',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'application_internetservicecustom_entry_portrange': {
            'params': ['adom', 'entry', 'internet-service-custom', 'port-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range',
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'application_list': {
            'params': ['adom', 'list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list',
                '/pm/config/adom/{adom}/obj/application/list/{list}',
                '/pm/config/global/obj/application/list',
                '/pm/config/global/obj/application/list/{list}'
            ]
        },
        'application_list_defaultnetworkservices': {
            'params': ['adom', 'default-network-services', 'list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/default-network-services',
                '/pm/config/adom/{adom}/obj/application/list/{list}/default-network-services/{default-network-services}',
                '/pm/config/global/obj/application/list/{list}/default-network-services',
                '/pm/config/global/obj/application/list/{list}/default-network-services/{default-network-services}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'application_list_entries': {
            'params': ['adom', 'entries', 'list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries',
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}',
                '/pm/config/global/obj/application/list/{list}/entries',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}'
            ]
        },
        'application_list_entries_parameters': {
            'params': ['adom', 'entries', 'list', 'parameters'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}/parameters',
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}/parameters/{parameters}',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}/parameters',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}/parameters/{parameters}'
            ]
        },
        'application_list_entries_parameters_members': {
            'params': ['adom', 'entries', 'list', 'members', 'parameters'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}/parameters/{parameters}/members',
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}/parameters/{parameters}/members/{members}',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}/parameters/{parameters}/members',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}/parameters/{parameters}/members/{members}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'arrpprofile': {
            'params': ['adom', 'arrp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/arrp-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/arrp-profile/{arrp-profile}',
                '/pm/config/global/obj/wireless-controller/arrp-profile',
                '/pm/config/global/obj/wireless-controller/arrp-profile/{arrp-profile}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'authentication_scheme': {
            'params': ['adom', 'scheme'],
            'urls': [
                '/pm/config/adom/{adom}/obj/authentication/scheme',
                '/pm/config/adom/{adom}/obj/authentication/scheme/{scheme}',
                '/pm/config/global/obj/authentication/scheme',
                '/pm/config/global/obj/authentication/scheme/{scheme}'
            ],
            'v_range': [['6.2.1', '']]
        },
        'bleprofile': {
            'params': ['adom', 'ble-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/ble-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/ble-profile/{ble-profile}',
                '/pm/config/global/obj/wireless-controller/ble-profile',
                '/pm/config/global/obj/wireless-controller/ble-profile/{ble-profile}'
            ]
        },
        'bonjourprofile': {
            'params': ['adom', 'bonjour-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile/{bonjour-profile}',
                '/pm/config/global/obj/wireless-controller/bonjour-profile',
                '/pm/config/global/obj/wireless-controller/bonjour-profile/{bonjour-profile}'
            ]
        },
        'bonjourprofile_policylist': {
            'params': ['adom', 'bonjour-profile', 'policy-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}',
                '/pm/config/global/obj/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list',
                '/pm/config/global/obj/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}'
            ]
        },
        'casb_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile',
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}',
                '/pm/config/global/obj/casb/profile',
                '/pm/config/global/obj/casb/profile/{profile}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_profile_saasapplication': {
            'params': ['adom', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application',
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_profile_saasapplication_accessrule': {
            'params': ['access-rule', 'adom', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule',
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule/{access-rule}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule/{access-rule}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_profile_saasapplication_accessrule_attributefilter': {
            'params': ['access-rule', 'adom', 'attribute-filter', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule/{access-rule}/attribute-filter',
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule/{access-rule}/attribute-filter/{attribute-'
                'filter}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule/{access-rule}/attribute-filter',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule/{access-rule}/attribute-filter/{attribute-filte'
                'r}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'casb_profile_saasapplication_advancedtenantcontrol': {
            'params': ['adom', 'advanced-tenant-control', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control',
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control/{advanced-tenant-control}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control/{advanced-tenant-control}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'casb_profile_saasapplication_advancedtenantcontrol_attribute': {
            'params': ['adom', 'advanced-tenant-control', 'attribute', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control/{advanced-tenant-control}/attr'
                'ibute',
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control/{advanced-tenant-control}/attr'
                'ibute/{attribute}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control/{advanced-tenant-control}/attribute',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control/{advanced-tenant-control}/attribute'
                '/{attribute}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'casb_profile_saasapplication_customcontrol': {
            'params': ['adom', 'custom-control', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control',
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_profile_saasapplication_customcontrol_attributefilter': {
            'params': ['adom', 'attribute-filter', 'custom-control', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/attribute-filter',
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/attribute-filter/{attr'
                'ibute-filter}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/attribute-filter',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/attribute-filter/{attribute'
                '-filter}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'casb_profile_saasapplication_customcontrol_option': {
            'params': ['adom', 'custom-control', 'option', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/option',
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/option/{option}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/option',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/option/{option}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_saasapplication': {
            'params': ['adom', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/saas-application',
                '/pm/config/adom/{adom}/obj/casb/saas-application/{saas-application}',
                '/pm/config/global/obj/casb/saas-application',
                '/pm/config/global/obj/casb/saas-application/{saas-application}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_saasapplication_inputattributes': {
            'params': ['adom', 'input-attributes', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/saas-application/{saas-application}/input-attributes',
                '/pm/config/adom/{adom}/obj/casb/saas-application/{saas-application}/input-attributes/{input-attributes}',
                '/pm/config/global/obj/casb/saas-application/{saas-application}/input-attributes',
                '/pm/config/global/obj/casb/saas-application/{saas-application}/input-attributes/{input-attributes}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'casb_saasapplication_outputattributes': {
            'params': ['adom', 'output-attributes', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/saas-application/{saas-application}/output-attributes',
                '/pm/config/adom/{adom}/obj/casb/saas-application/{saas-application}/output-attributes/{output-attributes}',
                '/pm/config/global/obj/casb/saas-application/{saas-application}/output-attributes',
                '/pm/config/global/obj/casb/saas-application/{saas-application}/output-attributes/{output-attributes}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'casb_useractivity': {
            'params': ['adom', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity',
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}',
                '/pm/config/global/obj/casb/user-activity',
                '/pm/config/global/obj/casb/user-activity/{user-activity}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_useractivity_controloptions': {
            'params': ['adom', 'control-options', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/control-options',
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/control-options/{control-options}',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/control-options',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/control-options/{control-options}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_useractivity_controloptions_operations': {
            'params': ['adom', 'control-options', 'operations', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/control-options/{control-options}/operations',
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/control-options/{control-options}/operations/{operations}',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/control-options/{control-options}/operations',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/control-options/{control-options}/operations/{operations}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_useractivity_match': {
            'params': ['adom', 'match', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match',
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match/{match}',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/match',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/match/{match}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_useractivity_match_rules': {
            'params': ['adom', 'match', 'rules', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match/{match}/rules',
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match/{match}/rules/{rules}',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/match/{match}/rules',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/match/{match}/rules/{rules}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_useractivity_match_tenantextraction': {
            'params': ['adom', 'match', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match/{match}/tenant-extraction',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/match/{match}/tenant-extraction'
            ],
            'v_range': [['7.6.2', '']]
        },
        'casb_useractivity_match_tenantextraction_filters': {
            'params': ['adom', 'filters', 'match', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match/{match}/tenant-extraction/filters',
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match/{match}/tenant-extraction/filters/{filters}',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/match/{match}/tenant-extraction/filters',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/match/{match}/tenant-extraction/filters/{filters}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'certificate_template': {
            'params': ['adom', 'template'],
            'urls': [
                '/pm/config/adom/{adom}/obj/certificate/template',
                '/pm/config/adom/{adom}/obj/certificate/template/{template}',
                '/pm/config/global/obj/certificate/template',
                '/pm/config/global/obj/certificate/template/{template}'
            ]
        },
        'cifs_domaincontroller': {
            'params': ['adom', 'domain-controller'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cifs/domain-controller',
                '/pm/config/adom/{adom}/obj/cifs/domain-controller/{domain-controller}',
                '/pm/config/global/obj/cifs/domain-controller',
                '/pm/config/global/obj/cifs/domain-controller/{domain-controller}'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'cifs_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cifs/profile',
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}',
                '/pm/config/global/obj/cifs/profile',
                '/pm/config/global/obj/cifs/profile/{profile}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'cifs_profile_filefilter': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/file-filter',
                '/pm/config/global/obj/cifs/profile/{profile}/file-filter'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'cifs_profile_filefilter_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/file-filter/entries',
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/global/obj/cifs/profile/{profile}/file-filter/entries',
                '/pm/config/global/obj/cifs/profile/{profile}/file-filter/entries/{entries}'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'cifs_profile_serverkeytab': {
            'params': ['adom', 'profile', 'server-keytab'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/server-keytab',
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/server-keytab/{server-keytab}',
                '/pm/config/global/obj/cifs/profile/{profile}/server-keytab',
                '/pm/config/global/obj/cifs/profile/{profile}/server-keytab/{server-keytab}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'cloud_orchestaws': {
            'params': ['adom', 'orchest-aws'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cloud/orchest-aws',
                '/pm/config/adom/{adom}/obj/cloud/orchest-aws/{orchest-aws}',
                '/pm/config/global/obj/cloud/orchest-aws',
                '/pm/config/global/obj/cloud/orchest-aws/{orchest-aws}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'cloud_orchestawsconnector': {
            'params': ['adom', 'orchest-awsconnector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cloud/orchest-awsconnector',
                '/pm/config/adom/{adom}/obj/cloud/orchest-awsconnector/{orchest-awsconnector}',
                '/pm/config/global/obj/cloud/orchest-awsconnector',
                '/pm/config/global/obj/cloud/orchest-awsconnector/{orchest-awsconnector}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'cloud_orchestawstemplate_autoscaleexistingvpc': {
            'params': ['adom', 'autoscale-existing-vpc'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-existing-vpc',
                '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-existing-vpc/{autoscale-existing-vpc}',
                '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-existing-vpc',
                '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-existing-vpc/{autoscale-existing-vpc}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'cloud_orchestawstemplate_autoscalenewvpc': {
            'params': ['adom', 'autoscale-new-vpc'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-new-vpc',
                '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-new-vpc/{autoscale-new-vpc}',
                '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-new-vpc',
                '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-new-vpc/{autoscale-new-vpc}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'cloud_orchestawstemplate_autoscaletgwnewvpc': {
            'params': ['adom', 'autoscale-tgw-new-vpc'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc',
                '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc/{autoscale-tgw-new-vpc}',
                '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc',
                '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc/{autoscale-tgw-new-vpc}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'cloud_orchestration': {
            'params': ['adom', 'orchestration'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cloud/orchestration',
                '/pm/config/adom/{adom}/obj/cloud/orchestration/{orchestration}',
                '/pm/config/global/obj/cloud/orchestration',
                '/pm/config/global/obj/cloud/orchestration/{orchestration}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'credentialstore_domaincontroller': {
            'params': ['adom', 'domain-controller'],
            'urls': [
                '/pm/config/adom/{adom}/obj/credential-store/domain-controller',
                '/pm/config/adom/{adom}/obj/credential-store/domain-controller/{domain-controller}',
                '/pm/config/global/obj/credential-store/domain-controller',
                '/pm/config/global/obj/credential-store/domain-controller/{domain-controller}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'devprof_device_profile_fortianalyzer': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/device/profile/fortianalyzer'
            ]
        },
        'devprof_device_profile_fortiguard': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/device/profile/fortiguard'
            ]
        },
        'devprof_log_fortianalyzer_setting': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/fortianalyzer/setting'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_log_fortianalyzercloud_setting': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/fortianalyzer-cloud/setting'
            ],
            'v_range': [['6.2.1', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_log_syslogd_filter': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_log_syslogd_filter_excludelist': {
            'params': ['adom', 'devprof', 'exclude-list'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter/exclude-list',
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter/exclude-list/{exclude-list}'
            ],
            'v_range': [['7.0.4', '7.0.14']]
        },
        'devprof_log_syslogd_filter_excludelist_fields': {
            'params': ['adom', 'devprof', 'exclude-list', 'fields'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter/exclude-list/{exclude-list}/fields',
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter/exclude-list/{exclude-list}/fields/{fields}'
            ],
            'v_range': [['7.0.4', '7.0.14']]
        },
        'devprof_log_syslogd_filter_freestyle': {
            'params': ['adom', 'devprof', 'free-style'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter/free-style',
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter/free-style/{free-style}'
            ],
            'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']]
        },
        'devprof_log_syslogd_setting': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/setting'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_log_syslogd_setting_customfieldname': {
            'params': ['adom', 'custom-field-name', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/setting/custom-field-name',
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/setting/custom-field-name/{custom-field-name}'
            ],
            'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']]
        },
        'devprof_system_centralmanagement': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/central-management'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_centralmanagement_serverlist': {
            'params': ['adom', 'devprof', 'server-list'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/central-management/server-list',
                '/pm/config/adom/{adom}/devprof/{devprof}/system/central-management/server-list/{server-list}'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_dns': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/dns'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1']]
        },
        'devprof_system_emailserver': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/email-server'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_global': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/global'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_ntp': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/ntp'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_ntp_ntpserver': {
            'params': ['adom', 'devprof', 'ntpserver'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/ntp/ntpserver',
                '/pm/config/adom/{adom}/devprof/{devprof}/system/ntp/ntpserver/{ntpserver}'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_admin': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/admin'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_alertmail': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/alertmail'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_auth': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/auth'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_devicedetectionportal': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/device-detection-portal'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_ec': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/ec'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '7.2.1']]
        },
        'devprof_system_replacemsg_fortiguardwf': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/fortiguard-wf'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_ftp': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/ftp'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_http': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/http'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_mail': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/mail'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_mms': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/mms'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '7.6.2']]
        },
        'devprof_system_replacemsg_nacquar': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/nac-quar'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_nntp': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/nntp'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_spam': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/spam'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_sslvpn': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/sslvpn'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_trafficquota': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/traffic-quota'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_utm': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/utm'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_replacemsg_webproxy': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/replacemsg/webproxy'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_snmp_community': {
            'params': ['adom', 'community', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community',
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_snmp_community_hosts': {
            'params': ['adom', 'community', 'devprof', 'hosts'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}/hosts',
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}/hosts/{hosts}'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_snmp_community_hosts6': {
            'params': ['adom', 'community', 'devprof', 'hosts6'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}/hosts6',
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}/hosts6/{hosts6}'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_snmp_sysinfo': {
            'params': ['adom', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/sysinfo'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_snmp_user': {
            'params': ['adom', 'devprof', 'user'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user',
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user/{user}'
            ],
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'diameterfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/diameter-filter/profile',
                '/pm/config/adom/{adom}/obj/diameter-filter/profile/{profile}',
                '/pm/config/global/obj/diameter-filter/profile',
                '/pm/config/global/obj/diameter-filter/profile/{profile}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'dlp_datatype': {
            'params': ['adom', 'data-type'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/data-type',
                '/pm/config/adom/{adom}/obj/dlp/data-type/{data-type}',
                '/pm/config/global/obj/dlp/data-type',
                '/pm/config/global/obj/dlp/data-type/{data-type}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'dlp_dictionary': {
            'params': ['adom', 'dictionary'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/dictionary',
                '/pm/config/adom/{adom}/obj/dlp/dictionary/{dictionary}',
                '/pm/config/global/obj/dlp/dictionary',
                '/pm/config/global/obj/dlp/dictionary/{dictionary}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'dlp_dictionary_entries': {
            'params': ['adom', 'dictionary', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/dictionary/{dictionary}/entries',
                '/pm/config/adom/{adom}/obj/dlp/dictionary/{dictionary}/entries/{entries}',
                '/pm/config/global/obj/dlp/dictionary/{dictionary}/entries',
                '/pm/config/global/obj/dlp/dictionary/{dictionary}/entries/{entries}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'dlp_exactdatamatch': {
            'params': ['adom', 'exact-data-match'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/exact-data-match',
                '/pm/config/adom/{adom}/obj/dlp/exact-data-match/{exact-data-match}',
                '/pm/config/global/obj/dlp/exact-data-match',
                '/pm/config/global/obj/dlp/exact-data-match/{exact-data-match}'
            ],
            'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']]
        },
        'dlp_exactdatamatch_columns': {
            'params': ['adom', 'columns', 'exact-data-match'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/exact-data-match/{exact-data-match}/columns',
                '/pm/config/adom/{adom}/obj/dlp/exact-data-match/{exact-data-match}/columns/{columns}',
                '/pm/config/global/obj/dlp/exact-data-match/{exact-data-match}/columns',
                '/pm/config/global/obj/dlp/exact-data-match/{exact-data-match}/columns/{columns}'
            ],
            'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']]
        },
        'dlp_filepattern': {
            'params': ['adom', 'filepattern'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/filepattern',
                '/pm/config/adom/{adom}/obj/dlp/filepattern/{filepattern}',
                '/pm/config/global/obj/dlp/filepattern',
                '/pm/config/global/obj/dlp/filepattern/{filepattern}'
            ]
        },
        'dlp_filepattern_entries': {
            'params': ['adom', 'entries', 'filepattern'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/filepattern/{filepattern}/entries',
                '/pm/config/adom/{adom}/obj/dlp/filepattern/{filepattern}/entries/{entries}',
                '/pm/config/global/obj/dlp/filepattern/{filepattern}/entries',
                '/pm/config/global/obj/dlp/filepattern/{filepattern}/entries/{entries}'
            ]
        },
        'dlp_fpsensitivity': {
            'params': ['adom', 'fp-sensitivity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/fp-sensitivity',
                '/pm/config/adom/{adom}/obj/dlp/fp-sensitivity/{fp-sensitivity}',
                '/pm/config/global/obj/dlp/fp-sensitivity',
                '/pm/config/global/obj/dlp/fp-sensitivity/{fp-sensitivity}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'dlp_label': {
            'params': ['adom', 'label'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/label',
                '/pm/config/adom/{adom}/obj/dlp/label/{label}',
                '/pm/config/global/obj/dlp/label',
                '/pm/config/global/obj/dlp/label/{label}'
            ],
            'v_range': [['7.6.3', '']]
        },
        'dlp_label_entries': {
            'params': ['adom', 'entries', 'label'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/label/{label}/entries',
                '/pm/config/adom/{adom}/obj/dlp/label/{label}/entries/{entries}',
                '/pm/config/global/obj/dlp/label/{label}/entries',
                '/pm/config/global/obj/dlp/label/{label}/entries/{entries}'
            ],
            'v_range': [['7.6.3', '']]
        },
        'dlp_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/profile',
                '/pm/config/adom/{adom}/obj/dlp/profile/{profile}',
                '/pm/config/global/obj/dlp/profile',
                '/pm/config/global/obj/dlp/profile/{profile}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'dlp_profile_rule': {
            'params': ['adom', 'profile', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/profile/{profile}/rule',
                '/pm/config/adom/{adom}/obj/dlp/profile/{profile}/rule/{rule}',
                '/pm/config/global/obj/dlp/profile/{profile}/rule',
                '/pm/config/global/obj/dlp/profile/{profile}/rule/{rule}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'dlp_sensitivity': {
            'params': ['adom', 'sensitivity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensitivity',
                '/pm/config/adom/{adom}/obj/dlp/sensitivity/{sensitivity}',
                '/pm/config/global/obj/dlp/sensitivity',
                '/pm/config/global/obj/dlp/sensitivity/{sensitivity}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'dlp_sensor': {
            'params': ['adom', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor',
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}',
                '/pm/config/global/obj/dlp/sensor',
                '/pm/config/global/obj/dlp/sensor/{sensor}'
            ]
        },
        'dlp_sensor_entries': {
            'params': ['adom', 'entries', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/entries',
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/dlp/sensor/{sensor}/entries',
                '/pm/config/global/obj/dlp/sensor/{sensor}/entries/{entries}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'dlp_sensor_filter': {
            'params': ['adom', 'filter', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/filter',
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/dlp/sensor/{sensor}/filter',
                '/pm/config/global/obj/dlp/sensor/{sensor}/filter/{filter}'
            ]
        },
        'dnsfilter_domainfilter': {
            'params': ['adom', 'domain-filter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/domain-filter',
                '/pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{domain-filter}',
                '/pm/config/global/obj/dnsfilter/domain-filter',
                '/pm/config/global/obj/dnsfilter/domain-filter/{domain-filter}'
            ]
        },
        'dnsfilter_domainfilter_entries': {
            'params': ['adom', 'domain-filter', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{domain-filter}/entries',
                '/pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{domain-filter}/entries/{entries}',
                '/pm/config/global/obj/dnsfilter/domain-filter/{domain-filter}/entries',
                '/pm/config/global/obj/dnsfilter/domain-filter/{domain-filter}/entries/{entries}'
            ]
        },
        'dnsfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile',
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}',
                '/pm/config/global/obj/dnsfilter/profile',
                '/pm/config/global/obj/dnsfilter/profile/{profile}'
            ]
        },
        'dnsfilter_profile_dnstranslation': {
            'params': ['adom', 'dns-translation', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/dns-translation',
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/dns-translation/{dns-translation}',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/dns-translation',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/dns-translation/{dns-translation}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'dnsfilter_profile_domainfilter': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/domain-filter',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/domain-filter'
            ]
        },
        'dnsfilter_profile_ftgddns': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/ftgd-dns',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/ftgd-dns'
            ]
        },
        'dnsfilter_profile_ftgddns_filters': {
            'params': ['adom', 'filters', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/ftgd-dns/filters',
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/ftgd-dns/filters/{filters}',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/ftgd-dns/filters',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/ftgd-dns/filters/{filters}'
            ]
        },
        'dnsfilter_profile_urlfilter': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/urlfilter',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/urlfilter'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'dnsfilter_urlfilter': {
            'params': ['adom', 'urlfilter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/urlfilter',
                '/pm/config/adom/{adom}/obj/dnsfilter/urlfilter/{urlfilter}',
                '/pm/config/global/obj/dnsfilter/urlfilter',
                '/pm/config/global/obj/dnsfilter/urlfilter/{urlfilter}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'dnsfilter_urlfilter_entries': {
            'params': ['adom', 'entries', 'urlfilter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/urlfilter/{urlfilter}/entries',
                '/pm/config/adom/{adom}/obj/dnsfilter/urlfilter/{urlfilter}/entries/{entries}',
                '/pm/config/global/obj/dnsfilter/urlfilter/{urlfilter}/entries',
                '/pm/config/global/obj/dnsfilter/urlfilter/{urlfilter}/entries/{entries}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'dvmdb_adom': {
            'params': ['adom'],
            'urls': [
                '/dvmdb/adom',
                '/dvmdb/adom/{adom}'
            ]
        },
        'dvmdb_device': {
            'params': ['adom', 'device'],
            'urls': [
                '/dvmdb/adom/{adom}/device',
                '/dvmdb/adom/{adom}/device/{device}',
                '/dvmdb/device',
                '/dvmdb/device/{device}'
            ]
        },
        'dvmdb_device_haslave': {
            'params': ['adom', 'device', 'ha_slave'],
            'urls': [
                '/dvmdb/adom/{adom}/device/{device}/ha_slave',
                '/dvmdb/adom/{adom}/device/{device}/ha_slave/{ha_slave}',
                '/dvmdb/device/{device}/ha_slave',
                '/dvmdb/device/{device}/ha_slave/{ha_slave}'
            ]
        },
        'dvmdb_device_vdom': {
            'params': ['adom', 'device', 'vdom'],
            'urls': [
                '/dvmdb/adom/{adom}/device/{device}/vdom',
                '/dvmdb/adom/{adom}/device/{device}/vdom/{vdom}',
                '/dvmdb/device/{device}/vdom',
                '/dvmdb/device/{device}/vdom/{vdom}'
            ]
        },
        'dvmdb_folder': {
            'params': ['adom', 'folder'],
            'urls': [
                '/dvmdb/adom/{adom}/folder',
                '/dvmdb/adom/{adom}/folder/{folder}',
                '/dvmdb/folder',
                '/dvmdb/folder/{folder}'
            ],
            'v_range': [['6.4.2', '']]
        },
        'dvmdb_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/dvmdb/adom/{adom}/group',
                '/dvmdb/adom/{adom}/group/{group}',
                '/dvmdb/group',
                '/dvmdb/group/{group}'
            ]
        },
        'dvmdb_metafields_adom': {
            'params': [],
            'urls': [
                '/dvmdb/_meta_fields/adom'
            ]
        },
        'dvmdb_metafields_device': {
            'params': [],
            'urls': [
                '/dvmdb/_meta_fields/device'
            ]
        },
        'dvmdb_metafields_group': {
            'params': [],
            'urls': [
                '/dvmdb/_meta_fields/group'
            ]
        },
        'dvmdb_revision': {
            'params': ['adom', 'revision'],
            'urls': [
                '/dvmdb/adom/{adom}/revision',
                '/dvmdb/adom/{adom}/revision/{revision}',
                '/dvmdb/global/revision',
                '/dvmdb/global/revision/{revision}',
                '/dvmdb/revision',
                '/dvmdb/revision/{revision}'
            ]
        },
        'dvmdb_script': {
            'params': ['adom', 'script'],
            'urls': [
                '/dvmdb/adom/{adom}/script',
                '/dvmdb/adom/{adom}/script/{script}',
                '/dvmdb/global/script',
                '/dvmdb/global/script/{script}',
                '/dvmdb/script',
                '/dvmdb/script/{script}'
            ]
        },
        'dvmdb_script_log_latest': {
            'params': ['adom'],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/latest',
                '/dvmdb/global/script/log/latest'
            ]
        },
        'dvmdb_script_log_latest_device': {
            'params': ['adom', 'device_name'],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/latest/device/{device_name}',
                '/dvmdb/script/log/latest/device/{device_name}'
            ]
        },
        'dvmdb_script_log_list': {
            'params': ['adom'],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/list',
                '/dvmdb/global/script/log/list'
            ]
        },
        'dvmdb_script_log_list_device': {
            'params': ['adom', 'device_name'],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/list/device/{device_name}',
                '/dvmdb/script/log/list/device/{device_name}'
            ]
        },
        'dvmdb_script_log_output_device_logid': {
            'params': ['adom', 'device', 'log_id'],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/output/device/{device}/logid/{log_id}',
                '/dvmdb/script/log/output/device/{device}/logid/{log_id}'
            ]
        },
        'dvmdb_script_log_output_logid': {
            'params': ['adom', 'log_id'],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/output/logid/{log_id}',
                '/dvmdb/global/script/log/output/logid/{log_id}'
            ]
        },
        'dvmdb_script_log_summary': {
            'params': ['adom'],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/summary',
                '/dvmdb/global/script/log/summary'
            ]
        },
        'dvmdb_script_log_summary_device': {
            'params': ['adom', 'device_name'],
            'urls': [
                '/dvmdb/adom/{adom}/script/log/summary/device/{device_name}',
                '/dvmdb/script/log/summary/device/{device_name}'
            ]
        },
        'dvmdb_script_scriptschedule': {
            'params': ['adom', 'script', 'script_schedule'],
            'urls': [
                '/dvmdb/adom/{adom}/script/{script}/script_schedule',
                '/dvmdb/adom/{adom}/script/{script}/script_schedule/{script_schedule}',
                '/dvmdb/global/script/{script}/script_schedule',
                '/dvmdb/global/script/{script}/script_schedule/{script_schedule}',
                '/dvmdb/script/{script}/script_schedule',
                '/dvmdb/script/{script}/script_schedule/{script_schedule}'
            ]
        },
        'dvmdb_workflow': {
            'params': ['adom', 'workflow'],
            'urls': [
                '/dvmdb/adom/{adom}/workflow',
                '/dvmdb/adom/{adom}/workflow/{workflow}',
                '/dvmdb/global/workflow',
                '/dvmdb/global/workflow/{workflow}',
                '/dvmdb/workflow',
                '/dvmdb/workflow/{workflow}'
            ]
        },
        'dvmdb_workflow_wflog': {
            'params': ['adom', 'wflog', 'workflow'],
            'urls': [
                '/dvmdb/adom/{adom}/workflow/{workflow}/wflog',
                '/dvmdb/adom/{adom}/workflow/{workflow}/wflog/{wflog}',
                '/dvmdb/global/workflow/{workflow}/wflog',
                '/dvmdb/global/workflow/{workflow}/wflog/{wflog}',
                '/dvmdb/workflow/{workflow}/wflog',
                '/dvmdb/workflow/{workflow}/wflog/{wflog}'
            ]
        },
        'dvmdb_workspace_dirty': {
            'params': ['adom'],
            'urls': [
                '/dvmdb/adom/{adom}/workspace/dirty',
                '/dvmdb/global/workspace/dirty'
            ]
        },
        'dvmdb_workspace_dirty_dev': {
            'params': ['adom', 'device_name'],
            'urls': [
                '/dvmdb/adom/{adom}/workspace/dirty/dev/{device_name}'
            ]
        },
        'dvmdb_workspace_lockinfo': {
            'params': ['adom'],
            'urls': [
                '/dvmdb/adom/{adom}/workspace/lockinfo',
                '/dvmdb/global/workspace/lockinfo'
            ]
        },
        'dvmdb_workspace_lockinfo_dev': {
            'params': ['adom', 'device_name'],
            'urls': [
                '/dvmdb/adom/{adom}/workspace/lockinfo/dev/{device_name}'
            ]
        },
        'dvmdb_workspace_lockinfo_obj': {
            'params': ['adom', 'object_url_name'],
            'urls': [
                '/dvmdb/adom/{adom}/workspace/lockinfo/obj/{object_url_name}',
                '/dvmdb/global/workspace/lockinfo/obj/{object_url_name}'
            ]
        },
        'dvmdb_workspace_lockinfo_pkg': {
            'params': ['adom', 'package_path_name'],
            'urls': [
                '/dvmdb/adom/{adom}/workspace/lockinfo/pkg/{package_path_name}',
                '/dvmdb/global/workspace/lockinfo/pkg/{package_path_name}'
            ]
        },
        'dynamic_address': {
            'params': ['address', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/address',
                '/pm/config/adom/{adom}/obj/dynamic/address/{address}',
                '/pm/config/global/obj/dynamic/address',
                '/pm/config/global/obj/dynamic/address/{address}'
            ]
        },
        'dynamic_address_dynamicaddrmapping': {
            'params': ['address', 'adom', 'dynamic_addr_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/address/{address}/dynamic_addr_mapping',
                '/pm/config/adom/{adom}/obj/dynamic/address/{address}/dynamic_addr_mapping/{dynamic_addr_mapping}',
                '/pm/config/global/obj/dynamic/address/{address}/dynamic_addr_mapping',
                '/pm/config/global/obj/dynamic/address/{address}/dynamic_addr_mapping/{dynamic_addr_mapping}'
            ]
        },
        'dynamic_certificate_local': {
            'params': ['adom', 'local'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/certificate/local',
                '/pm/config/adom/{adom}/obj/dynamic/certificate/local/{local}',
                '/pm/config/global/obj/dynamic/certificate/local',
                '/pm/config/global/obj/dynamic/certificate/local/{local}'
            ]
        },
        'dynamic_certificate_local_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'local'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/certificate/local/{local}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/dynamic/certificate/local/{local}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/certificate/local/{local}/dynamic_mapping',
                '/pm/config/global/obj/dynamic/certificate/local/{local}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'dynamic_input_interface': {
            'params': ['adom', 'interface'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/input/interface',
                '/pm/config/adom/{adom}/obj/dynamic/input/interface/{interface}',
                '/pm/config/global/obj/dynamic/input/interface',
                '/pm/config/global/obj/dynamic/input/interface/{interface}'
            ],
            'v_range': [['6.2.2', '6.4.0']]
        },
        'dynamic_input_interface_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'interface'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/input/interface/{interface}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/dynamic/input/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/input/interface/{interface}/dynamic_mapping',
                '/pm/config/global/obj/dynamic/input/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
            ],
            'v_range': [['6.2.2', '6.4.0']]
        },
        'dynamic_interface': {
            'params': ['adom', 'interface'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/interface',
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}',
                '/pm/config/global/obj/dynamic/interface',
                '/pm/config/global/obj/dynamic/interface/{interface}'
            ]
        },
        'dynamic_interface_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'interface'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/interface/{interface}/dynamic_mapping',
                '/pm/config/global/obj/dynamic/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'dynamic_interface_platformmapping': {
            'params': ['adom', 'interface', 'platform_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}/platform_mapping',
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}/platform_mapping/{platform_mapping}',
                '/pm/config/global/obj/dynamic/interface/{interface}/platform_mapping',
                '/pm/config/global/obj/dynamic/interface/{interface}/platform_mapping/{platform_mapping}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'dynamic_ippool': {
            'params': ['adom', 'ippool'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/ippool',
                '/pm/config/adom/{adom}/obj/dynamic/ippool/{ippool}',
                '/pm/config/global/obj/dynamic/ippool',
                '/pm/config/global/obj/dynamic/ippool/{ippool}'
            ]
        },
        'dynamic_multicast_interface': {
            'params': ['adom', 'interface'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/multicast/interface',
                '/pm/config/adom/{adom}/obj/dynamic/multicast/interface/{interface}',
                '/pm/config/global/obj/dynamic/multicast/interface',
                '/pm/config/global/obj/dynamic/multicast/interface/{interface}'
            ]
        },
        'dynamic_multicast_interface_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'interface'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/multicast/interface/{interface}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/dynamic/multicast/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/multicast/interface/{interface}/dynamic_mapping',
                '/pm/config/global/obj/dynamic/multicast/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'dynamic_vip': {
            'params': ['adom', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vip',
                '/pm/config/adom/{adom}/obj/dynamic/vip/{vip}',
                '/pm/config/global/obj/dynamic/vip',
                '/pm/config/global/obj/dynamic/vip/{vip}'
            ]
        },
        'dynamic_virtualwanlink_members': {
            'params': ['adom', 'members'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members',
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{members}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/members',
                '/pm/config/global/obj/dynamic/virtual-wan-link/members/{members}'
            ],
            'v_range': [['6.0.0', '6.4.15']]
        },
        'dynamic_virtualwanlink_members_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'members'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{members}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{members}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/members/{members}/dynamic_mapping',
                '/pm/config/global/obj/dynamic/virtual-wan-link/members/{members}/dynamic_mapping/{dynamic_mapping}'
            ],
            'v_range': [['6.0.0', '6.4.15']]
        },
        'dynamic_virtualwanlink_neighbor': {
            'params': ['adom', 'neighbor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/neighbor',
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/neighbor/{neighbor}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/neighbor',
                '/pm/config/global/obj/dynamic/virtual-wan-link/neighbor/{neighbor}'
            ],
            'v_range': [['6.2.2', '6.4.15']]
        },
        'dynamic_virtualwanlink_neighbor_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'neighbor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/neighbor/{neighbor}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/neighbor/{neighbor}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/neighbor/{neighbor}/dynamic_mapping',
                '/pm/config/global/obj/dynamic/virtual-wan-link/neighbor/{neighbor}/dynamic_mapping/{dynamic_mapping}'
            ],
            'v_range': [['6.2.2', '6.4.15']]
        },
        'dynamic_virtualwanlink_server': {
            'params': ['adom', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/server',
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/server/{server}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/server',
                '/pm/config/global/obj/dynamic/virtual-wan-link/server/{server}'
            ],
            'v_range': [['6.0.0', '6.4.15']]
        },
        'dynamic_virtualwanlink_server_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/server/{server}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/server/{server}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/server/{server}/dynamic_mapping',
                '/pm/config/global/obj/dynamic/virtual-wan-link/server/{server}/dynamic_mapping/{dynamic_mapping}'
            ],
            'v_range': [['6.0.0', '6.4.15']]
        },
        'dynamic_vpntunnel': {
            'params': ['adom', 'vpntunnel'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vpntunnel',
                '/pm/config/adom/{adom}/obj/dynamic/vpntunnel/{vpntunnel}',
                '/pm/config/global/obj/dynamic/vpntunnel',
                '/pm/config/global/obj/dynamic/vpntunnel/{vpntunnel}'
            ]
        },
        'dynamic_vpntunnel_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vpntunnel'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vpntunnel/{vpntunnel}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/dynamic/vpntunnel/{vpntunnel}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/vpntunnel/{vpntunnel}/dynamic_mapping',
                '/pm/config/global/obj/dynamic/vpntunnel/{vpntunnel}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'emailfilter_blockallowlist': {
            'params': ['adom', 'block-allow-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/block-allow-list',
                '/pm/config/adom/{adom}/obj/emailfilter/block-allow-list/{block-allow-list}',
                '/pm/config/global/obj/emailfilter/block-allow-list',
                '/pm/config/global/obj/emailfilter/block-allow-list/{block-allow-list}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'emailfilter_blockallowlist_entries': {
            'params': ['adom', 'block-allow-list', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/block-allow-list/{block-allow-list}/entries',
                '/pm/config/adom/{adom}/obj/emailfilter/block-allow-list/{block-allow-list}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/block-allow-list/{block-allow-list}/entries',
                '/pm/config/global/obj/emailfilter/block-allow-list/{block-allow-list}/entries/{entries}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'emailfilter_bwl': {
            'params': ['adom', 'bwl'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/bwl',
                '/pm/config/adom/{adom}/obj/emailfilter/bwl/{bwl}',
                '/pm/config/global/obj/emailfilter/bwl',
                '/pm/config/global/obj/emailfilter/bwl/{bwl}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_bwl_entries': {
            'params': ['adom', 'bwl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/bwl/{bwl}/entries',
                '/pm/config/adom/{adom}/obj/emailfilter/bwl/{bwl}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/bwl/{bwl}/entries',
                '/pm/config/global/obj/emailfilter/bwl/{bwl}/entries/{entries}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_bword': {
            'params': ['adom', 'bword'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/bword',
                '/pm/config/adom/{adom}/obj/emailfilter/bword/{bword}',
                '/pm/config/global/obj/emailfilter/bword',
                '/pm/config/global/obj/emailfilter/bword/{bword}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_bword_entries': {
            'params': ['adom', 'bword', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/bword/{bword}/entries',
                '/pm/config/adom/{adom}/obj/emailfilter/bword/{bword}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/bword/{bword}/entries',
                '/pm/config/global/obj/emailfilter/bword/{bword}/entries/{entries}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_dnsbl': {
            'params': ['adom', 'dnsbl'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/dnsbl',
                '/pm/config/adom/{adom}/obj/emailfilter/dnsbl/{dnsbl}',
                '/pm/config/global/obj/emailfilter/dnsbl',
                '/pm/config/global/obj/emailfilter/dnsbl/{dnsbl}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_dnsbl_entries': {
            'params': ['adom', 'dnsbl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/dnsbl/{dnsbl}/entries',
                '/pm/config/adom/{adom}/obj/emailfilter/dnsbl/{dnsbl}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/dnsbl/{dnsbl}/entries',
                '/pm/config/global/obj/emailfilter/dnsbl/{dnsbl}/entries/{entries}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_fortishield': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/fortishield',
                '/pm/config/global/obj/emailfilter/fortishield'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_iptrust': {
            'params': ['adom', 'iptrust'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/iptrust',
                '/pm/config/adom/{adom}/obj/emailfilter/iptrust/{iptrust}',
                '/pm/config/global/obj/emailfilter/iptrust',
                '/pm/config/global/obj/emailfilter/iptrust/{iptrust}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_iptrust_entries': {
            'params': ['adom', 'entries', 'iptrust'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/iptrust/{iptrust}/entries',
                '/pm/config/adom/{adom}/obj/emailfilter/iptrust/{iptrust}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/iptrust/{iptrust}/entries',
                '/pm/config/global/obj/emailfilter/iptrust/{iptrust}/entries/{entries}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_mheader': {
            'params': ['adom', 'mheader'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/mheader',
                '/pm/config/adom/{adom}/obj/emailfilter/mheader/{mheader}',
                '/pm/config/global/obj/emailfilter/mheader',
                '/pm/config/global/obj/emailfilter/mheader/{mheader}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_mheader_entries': {
            'params': ['adom', 'entries', 'mheader'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/mheader/{mheader}/entries',
                '/pm/config/adom/{adom}/obj/emailfilter/mheader/{mheader}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/mheader/{mheader}/entries',
                '/pm/config/global/obj/emailfilter/mheader/{mheader}/entries/{entries}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_options': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/options',
                '/pm/config/global/obj/emailfilter/options'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}',
                '/pm/config/global/obj/emailfilter/profile',
                '/pm/config/global/obj/emailfilter/profile/{profile}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_profile_filefilter': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/file-filter',
                '/pm/config/global/obj/emailfilter/profile/{profile}/file-filter'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'emailfilter_profile_filefilter_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/file-filter/entries',
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/global/obj/emailfilter/profile/{profile}/file-filter/entries',
                '/pm/config/global/obj/emailfilter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'emailfilter_profile_gmail': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/gmail',
                '/pm/config/global/obj/emailfilter/profile/{profile}/gmail'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_profile_imap': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/imap',
                '/pm/config/global/obj/emailfilter/profile/{profile}/imap'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_profile_mapi': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/mapi',
                '/pm/config/global/obj/emailfilter/profile/{profile}/mapi'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_profile_msnhotmail': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/msn-hotmail',
                '/pm/config/global/obj/emailfilter/profile/{profile}/msn-hotmail'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_profile_otherwebmails': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/other-webmails',
                '/pm/config/global/obj/emailfilter/profile/{profile}/other-webmails'
            ],
            'v_range': [['6.4.2', '']]
        },
        'emailfilter_profile_pop3': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/pop3',
                '/pm/config/global/obj/emailfilter/profile/{profile}/pop3'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_profile_smtp': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/smtp',
                '/pm/config/global/obj/emailfilter/profile/{profile}/smtp'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_profile_yahoomail': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/yahoo-mail',
                '/pm/config/global/obj/emailfilter/profile/{profile}/yahoo-mail'
            ],
            'v_range': [['6.2.0', '6.2.0']]
        },
        'endpointcontrol_fctems': {
            'params': ['adom', 'fctems'],
            'urls': [
                '/pm/config/adom/{adom}/obj/endpoint-control/fctems',
                '/pm/config/adom/{adom}/obj/endpoint-control/fctems/{fctems}',
                '/pm/config/global/obj/endpoint-control/fctems',
                '/pm/config/global/obj/endpoint-control/fctems/{fctems}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_dataplan': {
            'params': ['adom', 'dataplan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/dataplan',
                '/pm/config/adom/{adom}/obj/extender-controller/dataplan/{dataplan}',
                '/pm/config/global/obj/extender-controller/dataplan',
                '/pm/config/global/obj/extender-controller/dataplan/{dataplan}'
            ],
            'v_range': [['6.4.4', '']]
        },
        'extendercontroller_extenderprofile': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}',
                '/pm/config/global/obj/extender-controller/extender-profile',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_cellular': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_cellular_controllerreport': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/controller-report',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/controller-report'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_cellular_modem1': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem1',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem1'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_cellular_modem1_autoswitch': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem1/auto-switch',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem1/auto-switch'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_cellular_modem2': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem2',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem2'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_cellular_modem2_autoswitch': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem2/auto-switch',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/modem2/auto-switch'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_cellular_smsnotification': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_cellular_smsnotification_alert': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/alert',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/alert'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_cellular_smsnotification_receiver': {
            'params': ['adom', 'extender-profile', 'receiver'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_lanextension': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/lan-extension',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/lan-extension'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_lanextension_backhaul': {
            'params': ['adom', 'backhaul', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul',
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_simprofile': {
            'params': ['adom', 'sim_profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/sim_profile',
                '/pm/config/adom/{adom}/obj/extender-controller/sim_profile/{sim_profile}',
                '/pm/config/global/obj/extender-controller/sim_profile',
                '/pm/config/global/obj/extender-controller/sim_profile/{sim_profile}'
            ],
            'v_range': [['6.4.4', '']]
        },
        'extendercontroller_simprofile_autoswitchprofile': {
            'params': ['adom', 'sim_profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/sim_profile/{sim_profile}/auto-switch_profile',
                '/pm/config/global/obj/extender-controller/sim_profile/{sim_profile}/auto-switch_profile'
            ],
            'v_range': [['6.4.4', '']]
        },
        'extendercontroller_template': {
            'params': ['adom', 'template'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/template',
                '/pm/config/adom/{adom}/obj/extender-controller/template/{template}',
                '/pm/config/global/obj/extender-controller/template',
                '/pm/config/global/obj/extender-controller/template/{template}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'extensioncontroller_dataplan': {
            'params': ['adom', 'dataplan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/dataplan',
                '/pm/config/adom/{adom}/obj/extension-controller/dataplan/{dataplan}',
                '/pm/config/global/obj/extension-controller/dataplan',
                '/pm/config/global/obj/extension-controller/dataplan/{dataplan}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile',
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}',
                '/pm/config/global/obj/extension-controller/extender-profile',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_cellular': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_cellular_controllerreport': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/controller-report',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/controller-report'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_cellular_modem1': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/modem1',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/modem1'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_cellular_modem1_autoswitch': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/modem1/auto-switch',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/modem1/auto-switch'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_cellular_modem2': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/modem2',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/modem2'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_cellular_modem2_autoswitch': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/modem2/auto-switch',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/modem2/auto-switch'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_cellular_smsnotification': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_cellular_smsnotification_alert': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/alert',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/alert'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_cellular_smsnotification_receiver': {
            'params': ['adom', 'extender-profile', 'receiver'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver',
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_lanextension': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/lan-extension',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/lan-extension'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_lanextension_backhaul': {
            'params': ['adom', 'backhaul', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/backhaul',
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/backhaul',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_lanextension_trafficsplitservices': {
            'params': ['adom', 'extender-profile', 'traffic-split-services'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/traffic-split-services',
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/traffic-split-services/{traffic-split-serv'
                'ices}',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/traffic-split-services',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/traffic-split-services/{traffic-split-services}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'extensioncontroller_extenderprofile_wifi': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/wifi',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/wifi'
            ],
            'v_range': [['7.4.3', '']]
        },
        'extensioncontroller_extenderprofile_wifi_radio1': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/wifi/radio-1',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/wifi/radio-1'
            ],
            'v_range': [['7.4.3', '']]
        },
        'extensioncontroller_extenderprofile_wifi_radio2': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/wifi/radio-2',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/wifi/radio-2'
            ],
            'v_range': [['7.4.3', '']]
        },
        'extensioncontroller_extendervap': {
            'params': ['adom', 'extender-vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-vap',
                '/pm/config/adom/{adom}/obj/extension-controller/extender-vap/{extender-vap}',
                '/pm/config/global/obj/extension-controller/extender-vap',
                '/pm/config/global/obj/extension-controller/extender-vap/{extender-vap}'
            ],
            'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']]
        },
        'filefilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/file-filter/profile',
                '/pm/config/adom/{adom}/obj/file-filter/profile/{profile}',
                '/pm/config/global/obj/file-filter/profile',
                '/pm/config/global/obj/file-filter/profile/{profile}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'filefilter_profile_rules': {
            'params': ['adom', 'profile', 'rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/file-filter/profile/{profile}/rules',
                '/pm/config/adom/{adom}/obj/file-filter/profile/{profile}/rules/{rules}',
                '/pm/config/global/obj/file-filter/profile/{profile}/rules',
                '/pm/config/global/obj/file-filter/profile/{profile}/rules/{rules}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'firewall_accessproxy': {
            'params': ['access-proxy', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}',
                '/pm/config/global/obj/firewall/access-proxy',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxy6': {
            'params': ['access-proxy6', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}',
                '/pm/config/global/obj/firewall/access-proxy6',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy6_apigateway': {
            'params': ['access-proxy6', 'adom', 'api-gateway'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy6_apigateway6': {
            'params': ['access-proxy6', 'adom', 'api-gateway6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy6_apigateway6_quic': {
            'params': ['access-proxy6', 'adom', 'api-gateway6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/quic',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/quic'
            ],
            'v_range': [['7.4.1', '']]
        },
        'firewall_accessproxy6_apigateway6_realservers': {
            'params': ['access-proxy6', 'adom', 'api-gateway6', 'realservers'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/realservers',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/realservers',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/realservers/{realservers}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy6_apigateway6_sslciphersuites': {
            'params': ['access-proxy6', 'adom', 'api-gateway6', 'ssl-cipher-suites'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/ssl-cipher-suites',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/ssl-cipher-suites',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy6_apigateway_quic': {
            'params': ['access-proxy6', 'adom', 'api-gateway'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/quic',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/quic'
            ],
            'v_range': [['7.4.1', '']]
        },
        'firewall_accessproxy6_apigateway_realservers': {
            'params': ['access-proxy6', 'adom', 'api-gateway', 'realservers'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/realservers',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/realservers',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/realservers/{realservers}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy6_apigateway_sslciphersuites': {
            'params': ['access-proxy6', 'adom', 'api-gateway', 'ssl-cipher-suites'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/ssl-cipher-suites',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/ssl-cipher-suites',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy_apigateway': {
            'params': ['access-proxy', 'adom', 'api-gateway'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxy_apigateway6': {
            'params': ['access-proxy', 'adom', 'api-gateway6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}'
            ],
            'v_range': [['7.0.1', '']]
        },
        'firewall_accessproxy_apigateway6_quic': {
            'params': ['access-proxy', 'adom', 'api-gateway6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/quic',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/quic'
            ],
            'v_range': [['7.4.1', '']]
        },
        'firewall_accessproxy_apigateway6_realservers': {
            'params': ['access-proxy', 'adom', 'api-gateway6', 'realservers'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/realservers',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/realservers',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/realservers/{realservers}'
            ],
            'v_range': [['7.0.1', '']]
        },
        'firewall_accessproxy_apigateway6_sslciphersuites': {
            'params': ['access-proxy', 'adom', 'api-gateway6', 'ssl-cipher-suites'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'v_range': [['7.0.1', '']]
        },
        'firewall_accessproxy_apigateway_quic': {
            'params': ['access-proxy', 'adom', 'api-gateway'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/quic',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/quic'
            ],
            'v_range': [['7.4.1', '']]
        },
        'firewall_accessproxy_apigateway_realservers': {
            'params': ['access-proxy', 'adom', 'api-gateway', 'realservers'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/realservers',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/realservers',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/realservers/{realservers}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxy_apigateway_sslciphersuites': {
            'params': ['access-proxy', 'adom', 'api-gateway', 'ssl-cipher-suites'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxy_realservers': {
            'params': ['access-proxy', 'adom', 'realservers'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/realservers',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/realservers',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/realservers/{realservers}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxy_serverpubkeyauthsettings': {
            'params': ['access-proxy', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings'
            ],
            'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxy_serverpubkeyauthsettings_certextension': {
            'params': ['access-proxy', 'adom', 'cert-extension'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings/cert-extension',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings/cert-extension/{cert-extension}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings/cert-extension',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings/cert-extension/{cert-extension}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxysshclientcert': {
            'params': ['access-proxy-ssh-client-cert', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-ssh-client-cert',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}',
                '/pm/config/global/obj/firewall/access-proxy-ssh-client-cert',
                '/pm/config/global/obj/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'firewall_accessproxysshclientcert_certextension': {
            'params': ['access-proxy-ssh-client-cert', 'adom', 'cert-extension'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}/cert-extension',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}/cert-extension/{cert-extension}',
                '/pm/config/global/obj/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}/cert-extension',
                '/pm/config/global/obj/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}/cert-extension/{cert-extension}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'firewall_accessproxyvirtualhost': {
            'params': ['access-proxy-virtual-host', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-virtual-host',
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-virtual-host/{access-proxy-virtual-host}',
                '/pm/config/global/obj/firewall/access-proxy-virtual-host',
                '/pm/config/global/obj/firewall/access-proxy-virtual-host/{access-proxy-virtual-host}'
            ],
            'v_range': [['7.0.1', '']]
        },
        'firewall_address': {
            'params': ['address', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address',
                '/pm/config/adom/{adom}/obj/firewall/address/{address}',
                '/pm/config/global/obj/firewall/address',
                '/pm/config/global/obj/firewall/address/{address}'
            ]
        },
        'firewall_address6': {
            'params': ['address6', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6',
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}',
                '/pm/config/global/obj/firewall/address6',
                '/pm/config/global/obj/firewall/address6/{address6}'
            ]
        },
        'firewall_address6_dynamicmapping': {
            'params': ['address6', 'adom', 'dynamic_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/address6/{address6}/dynamic_mapping',
                '/pm/config/global/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'firewall_address6_dynamicmapping_subnetsegment': {
            'params': ['address6', 'adom', 'dynamic_mapping', 'subnet-segment'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}/subnet-segment',
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}/subnet-segment/{subnet-segment}',
                '/pm/config/global/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}/subnet-segment',
                '/pm/config/global/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}/subnet-segment/{subnet-segment}'
            ],
            'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_address6_list': {
            'params': ['address6', 'adom', 'list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/list',
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/list/{list}',
                '/pm/config/global/obj/firewall/address6/{address6}/list',
                '/pm/config/global/obj/firewall/address6/{address6}/list/{list}'
            ]
        },
        'firewall_address6_profilelist': {
            'params': ['address6', 'adom', 'profile-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/profile-list',
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/profile-list/{profile-list}',
                '/pm/config/global/obj/firewall/address6/{address6}/profile-list',
                '/pm/config/global/obj/firewall/address6/{address6}/profile-list/{profile-list}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'firewall_address6_subnetsegment': {
            'params': ['address6', 'adom', 'subnet-segment'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/subnet-segment',
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/subnet-segment/{subnet-segment}',
                '/pm/config/global/obj/firewall/address6/{address6}/subnet-segment',
                '/pm/config/global/obj/firewall/address6/{address6}/subnet-segment/{subnet-segment}'
            ]
        },
        'firewall_address6_tagging': {
            'params': ['address6', 'adom', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/tagging',
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/address6/{address6}/tagging',
                '/pm/config/global/obj/firewall/address6/{address6}/tagging/{tagging}'
            ]
        },
        'firewall_address6template': {
            'params': ['address6-template', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template',
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}',
                '/pm/config/global/obj/firewall/address6-template',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}'
            ]
        },
        'firewall_address6template_subnetsegment': {
            'params': ['address6-template', 'adom', 'subnet-segment'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment',
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}'
            ]
        },
        'firewall_address6template_subnetsegment_values': {
            'params': ['address6-template', 'adom', 'subnet-segment', 'values'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values',
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values/{values}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values/{values}'
            ]
        },
        'firewall_address_dynamicmapping': {
            'params': ['address', 'adom', 'dynamic_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/address/{address}/dynamic_mapping',
                '/pm/config/global/obj/firewall/address/{address}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'firewall_address_list': {
            'params': ['address', 'adom', 'list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/list',
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/list/{list}',
                '/pm/config/global/obj/firewall/address/{address}/list',
                '/pm/config/global/obj/firewall/address/{address}/list/{list}'
            ]
        },
        'firewall_address_profilelist': {
            'params': ['address', 'adom', 'profile-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/profile-list',
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/profile-list/{profile-list}',
                '/pm/config/global/obj/firewall/address/{address}/profile-list',
                '/pm/config/global/obj/firewall/address/{address}/profile-list/{profile-list}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'firewall_address_tagging': {
            'params': ['address', 'adom', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/tagging',
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/address/{address}/tagging',
                '/pm/config/global/obj/firewall/address/{address}/tagging/{tagging}'
            ]
        },
        'firewall_addrgrp': {
            'params': ['addrgrp', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp',
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}',
                '/pm/config/global/obj/firewall/addrgrp',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}'
            ]
        },
        'firewall_addrgrp6': {
            'params': ['addrgrp6', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6',
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}',
                '/pm/config/global/obj/firewall/addrgrp6',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}'
            ]
        },
        'firewall_addrgrp6_dynamicmapping': {
            'params': ['addrgrp6', 'adom', 'dynamic_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}/dynamic_mapping',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'firewall_addrgrp6_tagging': {
            'params': ['addrgrp6', 'adom', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}/tagging',
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}/tagging',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}/tagging/{tagging}'
            ]
        },
        'firewall_addrgrp_dynamicmapping': {
            'params': ['addrgrp', 'adom', 'dynamic_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'firewall_addrgrp_tagging': {
            'params': ['addrgrp', 'adom', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/tagging',
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/tagging',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/tagging/{tagging}'
            ]
        },
        'firewall_carrierendpointbwl': {
            'params': ['adom', 'carrier-endpoint-bwl'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl',
                '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}',
                '/pm/config/global/obj/firewall/carrier-endpoint-bwl',
                '/pm/config/global/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'firewall_carrierendpointbwl_entries': {
            'params': ['adom', 'carrier-endpoint-bwl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries',
                '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries/{entries}',
                '/pm/config/global/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries',
                '/pm/config/global/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries/{entries}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'firewall_casbprofile': {
            'params': ['adom', 'casb-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/casb-profile',
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}',
                '/pm/config/global/obj/firewall/casb-profile',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}'
            ],
            'v_range': [['7.4.1', '7.4.1']]
        },
        'firewall_casbprofile_saasapplication': {
            'params': ['adom', 'casb-profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application',
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}'
            ],
            'v_range': [['7.4.1', '7.4.1']]
        },
        'firewall_casbprofile_saasapplication_accessrule': {
            'params': ['access-rule', 'adom', 'casb-profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/access-rule',
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/access-rule/{access-rule}',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/access-rule',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/access-rule/{access-rule}'
            ],
            'v_range': [['7.4.1', '7.4.1']]
        },
        'firewall_casbprofile_saasapplication_customcontrol': {
            'params': ['adom', 'casb-profile', 'custom-control', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control',
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control/{custom-control}',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control/{custom-control}'
            ],
            'v_range': [['7.4.1', '7.4.1']]
        },
        'firewall_casbprofile_saasapplication_customcontrol_option': {
            'params': ['adom', 'casb-profile', 'custom-control', 'option', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control/{custom-control}/option',
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control/{custom-control}/option/{'
                'option}',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control/{custom-control}/option',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control/{custom-control}/option/{optio'
                'n}'
            ],
            'v_range': [['7.4.1', '7.4.1']]
        },
        'firewall_decryptedtrafficmirror': {
            'params': ['adom', 'decrypted-traffic-mirror'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/decrypted-traffic-mirror',
                '/pm/config/adom/{adom}/obj/firewall/decrypted-traffic-mirror/{decrypted-traffic-mirror}',
                '/pm/config/global/obj/firewall/decrypted-traffic-mirror',
                '/pm/config/global/obj/firewall/decrypted-traffic-mirror/{decrypted-traffic-mirror}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'firewall_explicitproxyaddress': {
            'params': ['adom', 'explicit-proxy-address'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-address',
                '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-address/{explicit-proxy-address}',
                '/pm/config/global/obj/firewall/explicit-proxy-address',
                '/pm/config/global/obj/firewall/explicit-proxy-address/{explicit-proxy-address}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'firewall_explicitproxyaddress_headergroup': {
            'params': ['adom', 'explicit-proxy-address', 'header-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-address/{explicit-proxy-address}/header-group',
                '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-address/{explicit-proxy-address}/header-group/{header-group}',
                '/pm/config/global/obj/firewall/explicit-proxy-address/{explicit-proxy-address}/header-group',
                '/pm/config/global/obj/firewall/explicit-proxy-address/{explicit-proxy-address}/header-group/{header-group}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'firewall_explicitproxyaddrgrp': {
            'params': ['adom', 'explicit-proxy-addrgrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-addrgrp',
                '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-addrgrp/{explicit-proxy-addrgrp}',
                '/pm/config/global/obj/firewall/explicit-proxy-addrgrp',
                '/pm/config/global/obj/firewall/explicit-proxy-addrgrp/{explicit-proxy-addrgrp}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'firewall_gtp': {
            'params': ['adom', 'gtp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp',
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}',
                '/pm/config/global/obj/firewall/gtp',
                '/pm/config/global/obj/firewall/gtp/{gtp}'
            ]
        },
        'firewall_gtp_apn': {
            'params': ['adom', 'apn', 'gtp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/apn',
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/apn/{apn}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/apn',
                '/pm/config/global/obj/firewall/gtp/{gtp}/apn/{apn}'
            ]
        },
        'firewall_gtp_ieremovepolicy': {
            'params': ['adom', 'gtp', 'ie-remove-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ie-remove-policy',
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ie-remove-policy/{ie-remove-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ie-remove-policy',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ie-remove-policy/{ie-remove-policy}'
            ]
        },
        'firewall_gtp_ievalidation': {
            'params': ['adom', 'gtp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ie-validation',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ie-validation'
            ]
        },
        'firewall_gtp_imsi': {
            'params': ['adom', 'gtp', 'imsi'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/imsi',
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/imsi/{imsi}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/imsi',
                '/pm/config/global/obj/firewall/gtp/{gtp}/imsi/{imsi}'
            ]
        },
        'firewall_gtp_ippolicy': {
            'params': ['adom', 'gtp', 'ip-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ip-policy',
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ip-policy/{ip-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ip-policy',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ip-policy/{ip-policy}'
            ]
        },
        'firewall_gtp_messagefilter': {
            'params': ['adom', 'gtp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/message-filter',
                '/pm/config/global/obj/firewall/gtp/{gtp}/message-filter'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'firewall_gtp_messageratelimit': {
            'params': ['adom', 'gtp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/message-rate-limit',
                '/pm/config/global/obj/firewall/gtp/{gtp}/message-rate-limit'
            ]
        },
        'firewall_gtp_messageratelimitv0': {
            'params': ['adom', 'gtp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/message-rate-limit-v0',
                '/pm/config/global/obj/firewall/gtp/{gtp}/message-rate-limit-v0'
            ]
        },
        'firewall_gtp_messageratelimitv1': {
            'params': ['adom', 'gtp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/message-rate-limit-v1',
                '/pm/config/global/obj/firewall/gtp/{gtp}/message-rate-limit-v1'
            ]
        },
        'firewall_gtp_messageratelimitv2': {
            'params': ['adom', 'gtp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/message-rate-limit-v2',
                '/pm/config/global/obj/firewall/gtp/{gtp}/message-rate-limit-v2'
            ]
        },
        'firewall_gtp_noippolicy': {
            'params': ['adom', 'gtp', 'noip-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/noip-policy',
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/noip-policy/{noip-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/noip-policy',
                '/pm/config/global/obj/firewall/gtp/{gtp}/noip-policy/{noip-policy}'
            ]
        },
        'firewall_gtp_perapnshaper': {
            'params': ['adom', 'gtp', 'per-apn-shaper'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/per-apn-shaper',
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/per-apn-shaper/{per-apn-shaper}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/per-apn-shaper',
                '/pm/config/global/obj/firewall/gtp/{gtp}/per-apn-shaper/{per-apn-shaper}'
            ]
        },
        'firewall_gtp_policy': {
            'params': ['adom', 'gtp', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy',
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy/{policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/policy',
                '/pm/config/global/obj/firewall/gtp/{gtp}/policy/{policy}'
            ]
        },
        'firewall_gtp_policyv2': {
            'params': ['adom', 'gtp', 'policy-v2'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy-v2',
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy-v2/{policy-v2}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/policy-v2',
                '/pm/config/global/obj/firewall/gtp/{gtp}/policy-v2/{policy-v2}'
            ],
            'v_range': [['6.2.1', '']]
        },
        'firewall_identitybasedroute': {
            'params': ['adom', 'identity-based-route'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/identity-based-route',
                '/pm/config/adom/{adom}/obj/firewall/identity-based-route/{identity-based-route}',
                '/pm/config/global/obj/firewall/identity-based-route',
                '/pm/config/global/obj/firewall/identity-based-route/{identity-based-route}'
            ]
        },
        'firewall_identitybasedroute_rule': {
            'params': ['adom', 'identity-based-route', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/identity-based-route/{identity-based-route}/rule',
                '/pm/config/adom/{adom}/obj/firewall/identity-based-route/{identity-based-route}/rule/{rule}',
                '/pm/config/global/obj/firewall/identity-based-route/{identity-based-route}/rule',
                '/pm/config/global/obj/firewall/identity-based-route/{identity-based-route}/rule/{rule}'
            ]
        },
        'firewall_internetservice': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service',
                '/pm/config/global/obj/firewall/internet-service'
            ]
        },
        'firewall_internetservice_entry': {
            'params': ['adom', 'entry'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service/entry',
                '/pm/config/adom/{adom}/obj/firewall/internet-service/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service/entry',
                '/pm/config/global/obj/firewall/internet-service/entry/{entry}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'firewall_internetserviceaddition': {
            'params': ['adom', 'internet-service-addition'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}',
                '/pm/config/global/obj/firewall/internet-service-addition',
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}'
            ],
            'v_range': [['6.2.2', '']]
        },
        'firewall_internetserviceaddition_entry': {
            'params': ['adom', 'entry', 'internet-service-addition'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}/entry',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}/entry',
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}'
            ],
            'v_range': [['6.2.2', '']]
        },
        'firewall_internetserviceaddition_entry_portrange': {
            'params': ['adom', 'entry', 'internet-service-addition', 'port-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}/port-range',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}/port-range/{port-range}',
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}/port-range',
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}/port-range/{port-range}'
            ],
            'v_range': [['6.2.2', '']]
        },
        'firewall_internetservicecustom': {
            'params': ['adom', 'internet-service-custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}',
                '/pm/config/global/obj/firewall/internet-service-custom',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}'
            ]
        },
        'firewall_internetservicecustom_disableentry': {
            'params': ['adom', 'disable-entry', 'internet-service-custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'firewall_internetservicecustom_disableentry_iprange': {
            'params': ['adom', 'disable-entry', 'internet-service-custom', 'ip-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'firewall_internetservicecustom_entry': {
            'params': ['adom', 'entry', 'internet-service-custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/entry',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/entry',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}'
            ]
        },
        'firewall_internetservicecustom_entry_portrange': {
            'params': ['adom', 'entry', 'internet-service-custom', 'port-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}'
            ]
        },
        'firewall_internetservicecustomgroup': {
            'params': ['adom', 'internet-service-custom-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom-group',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom-group/{internet-service-custom-group}',
                '/pm/config/global/obj/firewall/internet-service-custom-group',
                '/pm/config/global/obj/firewall/internet-service-custom-group/{internet-service-custom-group}'
            ]
        },
        'firewall_internetserviceextension': {
            'params': ['adom', 'internet-service-extension'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}',
                '/pm/config/global/obj/firewall/internet-service-extension',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}'
            ],
            'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetserviceextension_disableentry': {
            'params': ['adom', 'disable-entry', 'internet-service-extension'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}'
            ],
            'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetserviceextension_disableentry_ip6range': {
            'params': ['adom', 'disable-entry', 'internet-service-extension', 'ip6-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip6-range',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip6-range/{ip6-ran'
                'ge}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip6-range',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip6-range/{ip6-range}'
            ],
            'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetserviceextension_disableentry_iprange': {
            'params': ['adom', 'disable-entry', 'internet-service-extension', 'ip-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip-range',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip-range/{ip-range'
                '}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip-range',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip-range/{ip-range}'
            ],
            'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetserviceextension_disableentry_portrange': {
            'params': ['adom', 'disable-entry', 'internet-service-extension', 'port-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/port-range',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/port-range/{port-r'
                'ange}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/port-range',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/port-range/{port-range}'
            ],
            'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetserviceextension_entry': {
            'params': ['adom', 'entry', 'internet-service-extension'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/entry',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/entry',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}'
            ],
            'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetserviceextension_entry_portrange': {
            'params': ['adom', 'entry', 'internet-service-extension', 'port-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}/port-range',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}/port-range/{port-range}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}/port-range',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}/port-range/{port-range}'
            ],
            'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetservicegroup': {
            'params': ['adom', 'internet-service-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-group',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-group/{internet-service-group}',
                '/pm/config/global/obj/firewall/internet-service-group',
                '/pm/config/global/obj/firewall/internet-service-group/{internet-service-group}'
            ]
        },
        'firewall_internetservicename': {
            'params': ['adom', 'internet-service-name'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-name',
                '/pm/config/adom/{adom}/obj/firewall/internet-service-name/{internet-service-name}',
                '/pm/config/global/obj/firewall/internet-service-name',
                '/pm/config/global/obj/firewall/internet-service-name/{internet-service-name}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'firewall_ippool': {
            'params': ['adom', 'ippool'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool',
                '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}',
                '/pm/config/global/obj/firewall/ippool',
                '/pm/config/global/obj/firewall/ippool/{ippool}'
            ]
        },
        'firewall_ippool6': {
            'params': ['adom', 'ippool6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool6',
                '/pm/config/adom/{adom}/obj/firewall/ippool6/{ippool6}',
                '/pm/config/global/obj/firewall/ippool6',
                '/pm/config/global/obj/firewall/ippool6/{ippool6}'
            ]
        },
        'firewall_ippool6_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'ippool6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool6/{ippool6}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/firewall/ippool6/{ippool6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/ippool6/{ippool6}/dynamic_mapping',
                '/pm/config/global/obj/firewall/ippool6/{ippool6}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'firewall_ippool_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'ippool'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/ippool/{ippool}/dynamic_mapping',
                '/pm/config/global/obj/firewall/ippool/{ippool}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'firewall_ippoolgrp': {
            'params': ['adom', 'ippool-grp', 'ippool_grp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool-grp',
                '/pm/config/adom/{adom}/obj/firewall/ippool-grp/{ippool-grp}',
                '/pm/config/adom/{adom}/obj/firewall/ippool_grp',
                '/pm/config/adom/{adom}/obj/firewall/ippool_grp/{ippool_grp}',
                '/pm/config/global/obj/firewall/ippool-grp',
                '/pm/config/global/obj/firewall/ippool-grp/{ippool-grp}',
                '/pm/config/global/obj/firewall/ippool_grp',
                '/pm/config/global/obj/firewall/ippool_grp/{ippool_grp}'
            ],
            'v_range': [['7.6.3', '']]
        },
        'firewall_ldbmonitor': {
            'params': ['adom', 'ldb-monitor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ldb-monitor',
                '/pm/config/adom/{adom}/obj/firewall/ldb-monitor/{ldb-monitor}',
                '/pm/config/global/obj/firewall/ldb-monitor',
                '/pm/config/global/obj/firewall/ldb-monitor/{ldb-monitor}'
            ]
        },
        'firewall_mmsprofile': {
            'params': ['adom', 'mms-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile',
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}',
                '/pm/config/global/obj/firewall/mms-profile',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'firewall_mmsprofile_dupe': {
            'params': ['adom', 'mms-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/dupe',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/dupe'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'firewall_mmsprofile_flood': {
            'params': ['adom', 'mms-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/flood',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/flood'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'firewall_mmsprofile_notification': {
            'params': ['adom', 'mms-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/notification',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/notification'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'firewall_mmsprofile_notifmsisdn': {
            'params': ['adom', 'mms-profile', 'notif-msisdn'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/notif-msisdn',
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/notif-msisdn/{notif-msisdn}',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/notif-msisdn',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/notif-msisdn/{notif-msisdn}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'firewall_mmsprofile_outbreakprevention': {
            'params': ['adom', 'mms-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/outbreak-prevention',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/outbreak-prevention'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'firewall_multicastaddress': {
            'params': ['adom', 'multicast-address'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address',
                '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}',
                '/pm/config/global/obj/firewall/multicast-address',
                '/pm/config/global/obj/firewall/multicast-address/{multicast-address}'
            ]
        },
        'firewall_multicastaddress6': {
            'params': ['adom', 'multicast-address6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address6',
                '/pm/config/adom/{adom}/obj/firewall/multicast-address6/{multicast-address6}',
                '/pm/config/global/obj/firewall/multicast-address6',
                '/pm/config/global/obj/firewall/multicast-address6/{multicast-address6}'
            ]
        },
        'firewall_multicastaddress6_tagging': {
            'params': ['adom', 'multicast-address6', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address6/{multicast-address6}/tagging',
                '/pm/config/adom/{adom}/obj/firewall/multicast-address6/{multicast-address6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/multicast-address6/{multicast-address6}/tagging',
                '/pm/config/global/obj/firewall/multicast-address6/{multicast-address6}/tagging/{tagging}'
            ]
        },
        'firewall_multicastaddress_tagging': {
            'params': ['adom', 'multicast-address', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}/tagging',
                '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/multicast-address/{multicast-address}/tagging',
                '/pm/config/global/obj/firewall/multicast-address/{multicast-address}/tagging/{tagging}'
            ]
        },
        'firewall_networkservicedynamic': {
            'params': ['adom', 'network-service-dynamic'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/network-service-dynamic',
                '/pm/config/adom/{adom}/obj/firewall/network-service-dynamic/{network-service-dynamic}',
                '/pm/config/global/obj/firewall/network-service-dynamic',
                '/pm/config/global/obj/firewall/network-service-dynamic/{network-service-dynamic}'
            ],
            'v_range': [['7.2.2', '']]
        },
        'firewall_profilegroup': {
            'params': ['adom', 'profile-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-group',
                '/pm/config/adom/{adom}/obj/firewall/profile-group/{profile-group}',
                '/pm/config/global/obj/firewall/profile-group',
                '/pm/config/global/obj/firewall/profile-group/{profile-group}'
            ]
        },
        'firewall_profileprotocoloptions': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options',
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}',
                '/pm/config/global/obj/firewall/profile-protocol-options',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}'
            ]
        },
        'firewall_profileprotocoloptions_cifs': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs'
            ],
            'v_range': [['6.2.0', '']]
        },
        'firewall_profileprotocoloptions_cifs_filefilter': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter'
            ],
            'v_range': [['6.4.2', '']]
        },
        'firewall_profileprotocoloptions_cifs_filefilter_entries': {
            'params': ['adom', 'entries', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries',
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries/{entries}',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries/{entries}'
            ],
            'v_range': [['6.4.2', '']]
        },
        'firewall_profileprotocoloptions_cifs_serverkeytab': {
            'params': ['adom', 'profile-protocol-options', 'server-keytab'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/server-keytab',
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/server-keytab/{server-keytab}',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/server-keytab',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/server-keytab/{server-keytab}'
            ],
            'v_range': [['6.4.2', '']]
        },
        'firewall_profileprotocoloptions_dns': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/dns',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/dns'
            ]
        },
        'firewall_profileprotocoloptions_ftp': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/ftp',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/ftp'
            ]
        },
        'firewall_profileprotocoloptions_http': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/http',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/http'
            ]
        },
        'firewall_profileprotocoloptions_imap': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/imap',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/imap'
            ]
        },
        'firewall_profileprotocoloptions_mailsignature': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/mail-signature',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/mail-signature'
            ]
        },
        'firewall_profileprotocoloptions_mapi': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/mapi',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/mapi'
            ]
        },
        'firewall_profileprotocoloptions_nntp': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/nntp',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/nntp'
            ]
        },
        'firewall_profileprotocoloptions_pop3': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/pop3',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/pop3'
            ]
        },
        'firewall_profileprotocoloptions_smtp': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/smtp',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/smtp'
            ]
        },
        'firewall_profileprotocoloptions_ssh': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/ssh',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/ssh'
            ],
            'v_range': [['6.2.2', '']]
        },
        'firewall_proxyaddress': {
            'params': ['adom', 'proxy-address'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address',
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}',
                '/pm/config/global/obj/firewall/proxy-address',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}'
            ]
        },
        'firewall_proxyaddress_headergroup': {
            'params': ['adom', 'header-group', 'proxy-address'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}/header-group',
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}/header-group/{header-group}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}/header-group',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}/header-group/{header-group}'
            ]
        },
        'firewall_proxyaddress_tagging': {
            'params': ['adom', 'proxy-address', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}/tagging',
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}/tagging',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}/tagging/{tagging}'
            ]
        },
        'firewall_proxyaddrgrp': {
            'params': ['adom', 'proxy-addrgrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp',
                '/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp/{proxy-addrgrp}',
                '/pm/config/global/obj/firewall/proxy-addrgrp',
                '/pm/config/global/obj/firewall/proxy-addrgrp/{proxy-addrgrp}'
            ]
        },
        'firewall_proxyaddrgrp_tagging': {
            'params': ['adom', 'proxy-addrgrp', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging',
                '/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging',
                '/pm/config/global/obj/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging/{tagging}'
            ]
        },
        'firewall_schedule_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/group',
                '/pm/config/adom/{adom}/obj/firewall/schedule/group/{group}',
                '/pm/config/global/obj/firewall/schedule/group',
                '/pm/config/global/obj/firewall/schedule/group/{group}'
            ]
        },
        'firewall_schedule_onetime': {
            'params': ['adom', 'onetime'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/onetime',
                '/pm/config/adom/{adom}/obj/firewall/schedule/onetime/{onetime}',
                '/pm/config/global/obj/firewall/schedule/onetime',
                '/pm/config/global/obj/firewall/schedule/onetime/{onetime}'
            ]
        },
        'firewall_schedule_recurring': {
            'params': ['adom', 'recurring'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/recurring',
                '/pm/config/adom/{adom}/obj/firewall/schedule/recurring/{recurring}',
                '/pm/config/global/obj/firewall/schedule/recurring',
                '/pm/config/global/obj/firewall/schedule/recurring/{recurring}'
            ]
        },
        'firewall_service_category': {
            'params': ['adom', 'category'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/category',
                '/pm/config/adom/{adom}/obj/firewall/service/category/{category}',
                '/pm/config/global/obj/firewall/service/category',
                '/pm/config/global/obj/firewall/service/category/{category}'
            ]
        },
        'firewall_service_custom': {
            'params': ['adom', 'custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/custom',
                '/pm/config/adom/{adom}/obj/firewall/service/custom/{custom}',
                '/pm/config/global/obj/firewall/service/custom',
                '/pm/config/global/obj/firewall/service/custom/{custom}'
            ]
        },
        'firewall_service_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/group',
                '/pm/config/adom/{adom}/obj/firewall/service/group/{group}',
                '/pm/config/global/obj/firewall/service/group',
                '/pm/config/global/obj/firewall/service/group/{group}'
            ]
        },
        'firewall_shaper_peripshaper': {
            'params': ['adom', 'per-ip-shaper'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaper/per-ip-shaper',
                '/pm/config/adom/{adom}/obj/firewall/shaper/per-ip-shaper/{per-ip-shaper}',
                '/pm/config/global/obj/firewall/shaper/per-ip-shaper',
                '/pm/config/global/obj/firewall/shaper/per-ip-shaper/{per-ip-shaper}'
            ]
        },
        'firewall_shaper_trafficshaper': {
            'params': ['adom', 'traffic-shaper'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaper/traffic-shaper',
                '/pm/config/adom/{adom}/obj/firewall/shaper/traffic-shaper/{traffic-shaper}',
                '/pm/config/global/obj/firewall/shaper/traffic-shaper',
                '/pm/config/global/obj/firewall/shaper/traffic-shaper/{traffic-shaper}'
            ]
        },
        'firewall_shapingprofile': {
            'params': ['adom', 'shaping-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaping-profile',
                '/pm/config/adom/{adom}/obj/firewall/shaping-profile/{shaping-profile}',
                '/pm/config/global/obj/firewall/shaping-profile',
                '/pm/config/global/obj/firewall/shaping-profile/{shaping-profile}'
            ]
        },
        'firewall_shapingprofile_shapingentries': {
            'params': ['adom', 'shaping-entries', 'shaping-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries',
                '/pm/config/adom/{adom}/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries/{shaping-entries}',
                '/pm/config/global/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries',
                '/pm/config/global/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries/{shaping-entries}'
            ]
        },
        'firewall_ssh_localca': {
            'params': ['adom', 'local-ca'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssh/local-ca',
                '/pm/config/adom/{adom}/obj/firewall/ssh/local-ca/{local-ca}',
                '/pm/config/global/obj/firewall/ssh/local-ca',
                '/pm/config/global/obj/firewall/ssh/local-ca/{local-ca}'
            ],
            'v_range': [['6.2.1', '']]
        },
        'firewall_sslsshprofile': {
            'params': ['adom', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile',
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}'
            ]
        },
        'firewall_sslsshprofile_dot': {
            'params': ['adom', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/dot',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/dot'
            ],
            'v_range': [['7.0.0', '']]
        },
        'firewall_sslsshprofile_echoutersni': {
            'params': ['adom', 'ech-outer-sni', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ech-outer-sni',
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ech-outer-sni/{ech-outer-sni}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ech-outer-sni',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ech-outer-sni/{ech-outer-sni}'
            ],
            'v_range': [['7.4.3', '']]
        },
        'firewall_sslsshprofile_ftps': {
            'params': ['adom', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ftps',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ftps'
            ]
        },
        'firewall_sslsshprofile_https': {
            'params': ['adom', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/https',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/https'
            ]
        },
        'firewall_sslsshprofile_imaps': {
            'params': ['adom', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/imaps',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/imaps'
            ]
        },
        'firewall_sslsshprofile_pop3s': {
            'params': ['adom', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/pop3s',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/pop3s'
            ]
        },
        'firewall_sslsshprofile_smtps': {
            'params': ['adom', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/smtps',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/smtps'
            ]
        },
        'firewall_sslsshprofile_ssh': {
            'params': ['adom', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssh',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssh'
            ]
        },
        'firewall_sslsshprofile_ssl': {
            'params': ['adom', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl'
            ]
        },
        'firewall_sslsshprofile_sslexempt': {
            'params': ['adom', 'ssl-exempt', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt',
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt/{ssl-exempt}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt/{ssl-exempt}'
            ]
        },
        'firewall_sslsshprofile_sslserver': {
            'params': ['adom', 'ssl-server', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server',
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}'
            ]
        },
        'firewall_trafficclass': {
            'params': ['adom', 'traffic-class'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/traffic-class',
                '/pm/config/adom/{adom}/obj/firewall/traffic-class/{traffic-class}',
                '/pm/config/global/obj/firewall/traffic-class',
                '/pm/config/global/obj/firewall/traffic-class/{traffic-class}'
            ],
            'v_range': [['6.2.2', '']]
        },
        'firewall_vendormac': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vendor-mac',
                '/pm/config/global/obj/firewall/vendor-mac'
            ],
            'v_range': [['7.2.4', '7.2.11'], ['7.4.1', '']]
        },
        'firewall_vip': {
            'params': ['adom', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip',
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}',
                '/pm/config/global/obj/firewall/vip',
                '/pm/config/global/obj/firewall/vip/{vip}'
            ]
        },
        'firewall_vip46': {
            'params': ['adom', 'vip46'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46',
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}',
                '/pm/config/global/obj/firewall/vip46',
                '/pm/config/global/obj/firewall/vip46/{vip46}'
            ]
        },
        'firewall_vip46_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vip46'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip46/{vip46}/dynamic_mapping',
                '/pm/config/global/obj/firewall/vip46/{vip46}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'firewall_vip46_realservers': {
            'params': ['adom', 'realservers', 'vip46'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/realservers',
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip46/{vip46}/realservers',
                '/pm/config/global/obj/firewall/vip46/{vip46}/realservers/{realservers}'
            ]
        },
        'firewall_vip6': {
            'params': ['adom', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6',
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}',
                '/pm/config/global/obj/firewall/vip6',
                '/pm/config/global/obj/firewall/vip6/{vip6}'
            ]
        },
        'firewall_vip64': {
            'params': ['adom', 'vip64'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64',
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}',
                '/pm/config/global/obj/firewall/vip64',
                '/pm/config/global/obj/firewall/vip64/{vip64}'
            ]
        },
        'firewall_vip64_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vip64'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip64/{vip64}/dynamic_mapping',
                '/pm/config/global/obj/firewall/vip64/{vip64}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'firewall_vip64_realservers': {
            'params': ['adom', 'realservers', 'vip64'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}/realservers',
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip64/{vip64}/realservers',
                '/pm/config/global/obj/firewall/vip64/{vip64}/realservers/{realservers}'
            ]
        },
        'firewall_vip6_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping',
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'firewall_vip6_dynamicmapping_realservers': {
            'params': ['adom', 'dynamic_mapping', 'realservers', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/realservers',
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/realservers',
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}'
            ],
            'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_vip6_dynamicmapping_sslciphersuites': {
            'params': ['adom', 'dynamic_mapping', 'ssl-cipher-suites', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites',
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites',
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_vip6_quic': {
            'params': ['adom', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/quic',
                '/pm/config/global/obj/firewall/vip6/{vip6}/quic'
            ],
            'v_range': [['7.4.2', '']]
        },
        'firewall_vip6_realservers': {
            'params': ['adom', 'realservers', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/realservers',
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/realservers',
                '/pm/config/global/obj/firewall/vip6/{vip6}/realservers/{realservers}'
            ]
        },
        'firewall_vip6_sslciphersuites': {
            'params': ['adom', 'ssl-cipher-suites', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/ssl-cipher-suites',
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/ssl-cipher-suites',
                '/pm/config/global/obj/firewall/vip6/{vip6}/ssl-cipher-suites/{ssl-cipher-suites}'
            ]
        },
        'firewall_vip6_sslserverciphersuites': {
            'params': ['adom', 'ssl-server-cipher-suites', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/ssl-server-cipher-suites',
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/ssl-server-cipher-suites/{ssl-server-cipher-suites}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/ssl-server-cipher-suites',
                '/pm/config/global/obj/firewall/vip6/{vip6}/ssl-server-cipher-suites/{ssl-server-cipher-suites}'
            ]
        },
        'firewall_vip_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'firewall_vip_dynamicmapping_realservers': {
            'params': ['adom', 'dynamic_mapping', 'realservers', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/realservers',
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/realservers',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}'
            ],
            'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_vip_dynamicmapping_sslciphersuites': {
            'params': ['adom', 'dynamic_mapping', 'ssl-cipher-suites', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites',
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_vip_gslbpublicips': {
            'params': ['adom', 'gslb-public-ips', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/gslb-public-ips',
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/gslb-public-ips/{gslb-public-ips}',
                '/pm/config/global/obj/firewall/vip/{vip}/gslb-public-ips',
                '/pm/config/global/obj/firewall/vip/{vip}/gslb-public-ips/{gslb-public-ips}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'firewall_vip_quic': {
            'params': ['adom', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/quic',
                '/pm/config/global/obj/firewall/vip/{vip}/quic'
            ],
            'v_range': [['7.4.1', '']]
        },
        'firewall_vip_realservers': {
            'params': ['adom', 'realservers', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/realservers',
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip/{vip}/realservers',
                '/pm/config/global/obj/firewall/vip/{vip}/realservers/{realservers}'
            ]
        },
        'firewall_vip_sslciphersuites': {
            'params': ['adom', 'ssl-cipher-suites', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/ssl-cipher-suites',
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/ssl-cipher-suites',
                '/pm/config/global/obj/firewall/vip/{vip}/ssl-cipher-suites/{ssl-cipher-suites}'
            ]
        },
        'firewall_vip_sslserverciphersuites': {
            'params': ['adom', 'ssl-server-cipher-suites', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/ssl-server-cipher-suites',
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/ssl-server-cipher-suites/{ssl-server-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/ssl-server-cipher-suites',
                '/pm/config/global/obj/firewall/vip/{vip}/ssl-server-cipher-suites/{ssl-server-cipher-suites}'
            ]
        },
        'firewall_vipgrp': {
            'params': ['adom', 'vipgrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp',
                '/pm/config/adom/{adom}/obj/firewall/vipgrp/{vipgrp}',
                '/pm/config/global/obj/firewall/vipgrp',
                '/pm/config/global/obj/firewall/vipgrp/{vipgrp}'
            ]
        },
        'firewall_vipgrp46': {
            'params': ['adom', 'vipgrp46'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp46',
                '/pm/config/adom/{adom}/obj/firewall/vipgrp46/{vipgrp46}',
                '/pm/config/global/obj/firewall/vipgrp46',
                '/pm/config/global/obj/firewall/vipgrp46/{vipgrp46}'
            ]
        },
        'firewall_vipgrp6': {
            'params': ['adom', 'vipgrp6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp6',
                '/pm/config/adom/{adom}/obj/firewall/vipgrp6/{vipgrp6}',
                '/pm/config/global/obj/firewall/vipgrp6',
                '/pm/config/global/obj/firewall/vipgrp6/{vipgrp6}'
            ]
        },
        'firewall_vipgrp64': {
            'params': ['adom', 'vipgrp64'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp64',
                '/pm/config/adom/{adom}/obj/firewall/vipgrp64/{vipgrp64}',
                '/pm/config/global/obj/firewall/vipgrp64',
                '/pm/config/global/obj/firewall/vipgrp64/{vipgrp64}'
            ]
        },
        'firewall_vipgrp_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vipgrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp/{vipgrp}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/firewall/vipgrp/{vipgrp}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vipgrp/{vipgrp}/dynamic_mapping',
                '/pm/config/global/obj/firewall/vipgrp/{vipgrp}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'firewall_wildcardfqdn_custom': {
            'params': ['adom', 'custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/custom',
                '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/custom/{custom}',
                '/pm/config/global/obj/firewall/wildcard-fqdn/custom',
                '/pm/config/global/obj/firewall/wildcard-fqdn/custom/{custom}'
            ]
        },
        'firewall_wildcardfqdn_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/group',
                '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/group/{group}',
                '/pm/config/global/obj/firewall/wildcard-fqdn/group',
                '/pm/config/global/obj/firewall/wildcard-fqdn/group/{group}'
            ]
        },
        'fmg_device_blueprint': {
            'params': ['adom', 'blueprint'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fmg/device/blueprint',
                '/pm/config/adom/{adom}/obj/fmg/device/blueprint/{blueprint}',
                '/pm/config/global/obj/fmg/device/blueprint',
                '/pm/config/global/obj/fmg/device/blueprint/{blueprint}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'fmg_fabric_authorization_template': {
            'params': ['adom', 'template'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fmg/fabric/authorization/template',
                '/pm/config/adom/{adom}/obj/fmg/fabric/authorization/template/{template}',
                '/pm/config/global/obj/fmg/fabric/authorization/template',
                '/pm/config/global/obj/fmg/fabric/authorization/template/{template}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'fmg_fabric_authorization_template_platforms': {
            'params': ['adom', 'platforms', 'template'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fmg/fabric/authorization/template/{template}/platforms',
                '/pm/config/adom/{adom}/obj/fmg/fabric/authorization/template/{template}/platforms/{platforms}',
                '/pm/config/global/obj/fmg/fabric/authorization/template/{template}/platforms',
                '/pm/config/global/obj/fmg/fabric/authorization/template/{template}/platforms/{platforms}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'fmg_sasemanager_settings': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fmg/sase-manager/settings',
                '/pm/config/global/obj/fmg/sase-manager/settings'
            ],
            'v_range': [['7.6.0', '7.6.1']]
        },
        'fmg_sasemanager_status': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fmg/sase-manager/status',
                '/pm/config/global/obj/fmg/sase-manager/status'
            ],
            'v_range': [['7.6.0', '7.6.1']]
        },
        'fmg_variable': {
            'params': ['adom', 'variable'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fmg/variable',
                '/pm/config/adom/{adom}/obj/fmg/variable/{variable}',
                '/pm/config/global/obj/fmg/variable',
                '/pm/config/global/obj/fmg/variable/{variable}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'fmg_variable_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'variable'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fmg/variable/{variable}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/fmg/variable/{variable}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/fmg/variable/{variable}/dynamic_mapping',
                '/pm/config/global/obj/fmg/variable/{variable}/dynamic_mapping/{dynamic_mapping}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'fmupdate_analyzer_virusreport': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/analyzer/virusreport'
            ]
        },
        'fmupdate_avips_advancedlog': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/av-ips/advanced-log'
            ]
        },
        'fmupdate_avips_webproxy': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/av-ips/web-proxy'
            ],
            'v_range': [['6.0.0', '7.4.0']]
        },
        'fmupdate_customurllist': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/custom-url-list'
            ]
        },
        'fmupdate_diskquota': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/disk-quota'
            ]
        },
        'fmupdate_fctservices': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/fct-services'
            ]
        },
        'fmupdate_fdssetting': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/fds-setting'
            ]
        },
        'fmupdate_fdssetting_pushoverride': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override'
            ]
        },
        'fmupdate_fdssetting_pushoverridetoclient': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override-to-client'
            ]
        },
        'fmupdate_fdssetting_pushoverridetoclient_announceip': {
            'params': ['announce-ip'],
            'urls': [
                '/cli/global/fmupdate/fds-setting/push-override-to-client/announce-ip',
                '/cli/global/fmupdate/fds-setting/push-override-to-client/announce-ip/{announce-ip}'
            ]
        },
        'fmupdate_fdssetting_serveroverride': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/fds-setting/server-override'
            ]
        },
        'fmupdate_fdssetting_serveroverride_servlist': {
            'params': ['servlist'],
            'urls': [
                '/cli/global/fmupdate/fds-setting/server-override/servlist',
                '/cli/global/fmupdate/fds-setting/server-override/servlist/{servlist}'
            ]
        },
        'fmupdate_fdssetting_updateschedule': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/fds-setting/update-schedule'
            ]
        },
        'fmupdate_fgdsetting': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/fgd-setting'
            ],
            'v_range': [['7.6.3', '']]
        },
        'fmupdate_fgdsetting_serveroverride': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/fgd-setting/server-override'
            ],
            'v_range': [['7.6.3', '']]
        },
        'fmupdate_fgdsetting_serveroverride_servlist': {
            'params': ['servlist'],
            'urls': [
                '/cli/global/fmupdate/fgd-setting/server-override/servlist',
                '/cli/global/fmupdate/fgd-setting/server-override/servlist/{servlist}'
            ],
            'v_range': [['7.6.3', '']]
        },
        'fmupdate_fwmsetting': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/fwm-setting'
            ],
            'v_range': [['6.2.2', '']]
        },
        'fmupdate_fwmsetting_upgradetimeout': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/fwm-setting/upgrade-timeout'
            ],
            'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']]
        },
        'fmupdate_multilayer': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/multilayer'
            ]
        },
        'fmupdate_publicnetwork': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/publicnetwork'
            ]
        },
        'fmupdate_serveraccesspriorities': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/server-access-priorities'
            ]
        },
        'fmupdate_serveraccesspriorities_privateserver': {
            'params': ['private-server'],
            'urls': [
                '/cli/global/fmupdate/server-access-priorities/private-server',
                '/cli/global/fmupdate/server-access-priorities/private-server/{private-server}'
            ]
        },
        'fmupdate_serveroverridestatus': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/server-override-status'
            ]
        },
        'fmupdate_service': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/service'
            ]
        },
        'fmupdate_webspam_fgdsetting': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'fmupdate_webspam_fgdsetting_serveroverride': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting/server-override'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'fmupdate_webspam_fgdsetting_serveroverride_servlist': {
            'params': ['servlist'],
            'urls': [
                '/cli/global/fmupdate/web-spam/fgd-setting/server-override/servlist',
                '/cli/global/fmupdate/web-spam/fgd-setting/server-override/servlist/{servlist}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'fmupdate_webspam_webproxy': {
            'params': [],
            'urls': [
                '/cli/global/fmupdate/web-spam/web-proxy'
            ],
            'v_range': [['6.0.0', '7.4.0']]
        },
        'footer_consolidated_policy': {
            'params': ['adom', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/footer/consolidated/policy',
                '/pm/config/adom/{adom}/obj/global/footer/consolidated/policy/{policy}'
            ],
            'v_range': [['6.0.0', '7.0.4'], ['7.2.0', '7.2.1']]
        },
        'footer_policy': {
            'params': ['adom', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/footer/policy',
                '/pm/config/adom/{adom}/obj/global/footer/policy/{policy}'
            ],
            'v_range': [['6.0.0', '7.0.4'], ['7.2.0', '7.2.1']]
        },
        'footer_policy6': {
            'params': ['adom', 'policy6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/footer/policy6',
                '/pm/config/adom/{adom}/obj/global/footer/policy6/{policy6}'
            ],
            'v_range': [['6.0.0', '7.0.4'], ['7.2.0', '7.2.1']]
        },
        'footer_policy6_identitybasedpolicy6': {
            'params': ['adom', 'identity-based-policy6', 'policy6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/footer/policy6/{policy6}/identity-based-policy6',
                '/pm/config/adom/{adom}/obj/global/footer/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'v_range': [['6.0.0', '6.2.0']]
        },
        'footer_policy_identitybasedpolicy': {
            'params': ['adom', 'identity-based-policy', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/footer/policy/{policy}/identity-based-policy',
                '/pm/config/adom/{adom}/obj/global/footer/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'v_range': [['6.0.0', '6.2.0']]
        },
        'footer_shapingpolicy': {
            'params': ['adom', 'shaping-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/footer/shaping-policy',
                '/pm/config/adom/{adom}/obj/global/footer/shaping-policy/{shaping-policy}'
            ],
            'v_range': [['6.0.0', '7.0.4'], ['7.2.0', '7.2.1']]
        },
        'fsp_vlan': {
            'params': ['adom', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}',
                '/pm/config/global/obj/fsp/vlan',
                '/pm/config/global/obj/fsp/vlan/{vlan}'
            ]
        },
        'fsp_vlan_dhcpserver': {
            'params': ['adom', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server'
            ]
        },
        'fsp_vlan_dhcpserver_excluderange': {
            'params': ['adom', 'exclude-range', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/exclude-range',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/exclude-range/{exclude-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/exclude-range',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/exclude-range/{exclude-range}'
            ]
        },
        'fsp_vlan_dhcpserver_iprange': {
            'params': ['adom', 'ip-range', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/ip-range',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/ip-range/{ip-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/ip-range',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/ip-range/{ip-range}'
            ]
        },
        'fsp_vlan_dhcpserver_options': {
            'params': ['adom', 'options', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/options',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/options/{options}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/options',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/options/{options}'
            ]
        },
        'fsp_vlan_dhcpserver_reservedaddress': {
            'params': ['adom', 'reserved-address', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/reserved-address',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/reserved-address/{reserved-address}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/reserved-address',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/reserved-address/{reserved-address}'
            ]
        },
        'fsp_vlan_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'fsp_vlan_dynamicmapping_dhcpserver': {
            'params': ['adom', 'dynamic_mapping', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server'
            ],
            'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_dhcpserver_excluderange': {
            'params': ['adom', 'dynamic_mapping', 'exclude-range', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/exclude-range',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/exclude-range/{exclude-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/exclude-range',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/exclude-range/{exclude-range}'
            ],
            'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_dhcpserver_iprange': {
            'params': ['adom', 'dynamic_mapping', 'ip-range', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range/{ip-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range/{ip-range}'
            ],
            'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_dhcpserver_options': {
            'params': ['adom', 'dynamic_mapping', 'options', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/options',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/options/{options}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/options',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/options/{options}'
            ],
            'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_dhcpserver_reservedaddress': {
            'params': ['adom', 'dynamic_mapping', 'reserved-address', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/reserved-address',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/reserved-address/{reserved-address}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/reserved-address',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/reserved-address/{reserved-address}'
            ],
            'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface': {
            'params': ['adom', 'dynamic_mapping', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface'
            ],
            'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_ipv6': {
            'params': ['adom', 'dynamic_mapping', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6'
            ],
            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist': {
            'params': ['adom', 'dynamic_mapping', 'ip6-delegated-prefix-list', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-delegated-prefix-list',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-'
                'list}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-delegated-prefix-list',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}'
            ],
            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6extraaddr': {
            'params': ['adom', 'dynamic_mapping', 'ip6-extra-addr', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-extra-addr',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-extra-addr',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}'
            ],
            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6prefixlist': {
            'params': ['adom', 'dynamic_mapping', 'ip6-prefix-list', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-prefix-list',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-prefix-list',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}'
            ],
            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_vrrp6': {
            'params': ['adom', 'dynamic_mapping', 'vlan', 'vrrp6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/vrrp6',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/vrrp6/{vrrp6}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/vrrp6',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/vrrp6/{vrrp6}'
            ],
            'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_secondaryip': {
            'params': ['adom', 'dynamic_mapping', 'secondaryip', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/secondaryip',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/secondaryip/{secondaryip}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/secondaryip',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/secondaryip/{secondaryip}'
            ],
            'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_vrrp': {
            'params': ['adom', 'dynamic_mapping', 'vlan', 'vrrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}'
            ],
            'v_range': [['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_vrrp_proxyarp': {
            'params': ['adom', 'dynamic_mapping', 'proxy-arp', 'vlan', 'vrrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}/proxy-arp',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}/proxy-arp/{proxy-arp}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}/proxy-arp',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}/proxy-arp/{proxy-arp}'
            ],
            'v_range': [['7.4.0', '7.4.0']]
        },
        'fsp_vlan_interface': {
            'params': ['adom', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface'
            ]
        },
        'fsp_vlan_interface_ipv6': {
            'params': ['adom', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6'
            ]
        },
        'fsp_vlan_interface_ipv6_ip6delegatedprefixlist': {
            'params': ['adom', 'ip6-delegated-prefix-list', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-delegated-prefix-list',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-delegated-prefix-list',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}'
            ],
            'v_range': [['6.2.2', '']]
        },
        'fsp_vlan_interface_ipv6_ip6extraaddr': {
            'params': ['adom', 'ip6-extra-addr', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-extra-addr',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-extra-addr',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}'
            ],
            'v_range': [['6.2.2', '']]
        },
        'fsp_vlan_interface_ipv6_ip6prefixlist': {
            'params': ['adom', 'ip6-prefix-list', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-prefix-list',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-prefix-list',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}'
            ],
            'v_range': [['6.2.2', '']]
        },
        'fsp_vlan_interface_ipv6_vrrp6': {
            'params': ['adom', 'vlan', 'vrrp6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/vrrp6',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/vrrp6/{vrrp6}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/vrrp6',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/vrrp6/{vrrp6}'
            ],
            'v_range': [['6.2.2', '']]
        },
        'fsp_vlan_interface_secondaryip': {
            'params': ['adom', 'secondaryip', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/secondaryip',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/secondaryip/{secondaryip}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/secondaryip',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/secondaryip/{secondaryip}'
            ]
        },
        'fsp_vlan_interface_vrrp': {
            'params': ['adom', 'vlan', 'vrrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/vrrp',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/vrrp',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}'
            ]
        },
        'fsp_vlan_interface_vrrp_proxyarp': {
            'params': ['adom', 'proxy-arp', 'vlan', 'vrrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}/proxy-arp',
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}/proxy-arp/{proxy-arp}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}/proxy-arp',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}/proxy-arp/{proxy-arp}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'gtp_apn': {
            'params': ['adom', 'apn'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/apn',
                '/pm/config/adom/{adom}/obj/gtp/apn/{apn}',
                '/pm/config/global/obj/gtp/apn',
                '/pm/config/global/obj/gtp/apn/{apn}'
            ]
        },
        'gtp_apngrp': {
            'params': ['adom', 'apngrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/apngrp',
                '/pm/config/adom/{adom}/obj/gtp/apngrp/{apngrp}',
                '/pm/config/global/obj/gtp/apngrp',
                '/pm/config/global/obj/gtp/apngrp/{apngrp}'
            ]
        },
        'gtp_ieallowlist': {
            'params': ['adom', 'ie-allow-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-allow-list',
                '/pm/config/adom/{adom}/obj/gtp/ie-allow-list/{ie-allow-list}',
                '/pm/config/global/obj/gtp/ie-allow-list',
                '/pm/config/global/obj/gtp/ie-allow-list/{ie-allow-list}'
            ],
            'v_range': [['7.2.9', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.2', '']]
        },
        'gtp_ieallowlist_entries': {
            'params': ['adom', 'entries', 'ie-allow-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-allow-list/{ie-allow-list}/entries',
                '/pm/config/adom/{adom}/obj/gtp/ie-allow-list/{ie-allow-list}/entries/{entries}',
                '/pm/config/global/obj/gtp/ie-allow-list/{ie-allow-list}/entries',
                '/pm/config/global/obj/gtp/ie-allow-list/{ie-allow-list}/entries/{entries}'
            ],
            'v_range': [['7.2.9', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.2', '']]
        },
        'gtp_iewhitelist': {
            'params': ['adom', 'ie-white-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-white-list',
                '/pm/config/adom/{adom}/obj/gtp/ie-white-list/{ie-white-list}',
                '/pm/config/global/obj/gtp/ie-white-list',
                '/pm/config/global/obj/gtp/ie-white-list/{ie-white-list}'
            ]
        },
        'gtp_iewhitelist_entries': {
            'params': ['adom', 'entries', 'ie-white-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-white-list/{ie-white-list}/entries',
                '/pm/config/adom/{adom}/obj/gtp/ie-white-list/{ie-white-list}/entries/{entries}',
                '/pm/config/global/obj/gtp/ie-white-list/{ie-white-list}/entries',
                '/pm/config/global/obj/gtp/ie-white-list/{ie-white-list}/entries/{entries}'
            ]
        },
        'gtp_messagefilterv0v1': {
            'params': ['adom', 'message-filter-v0v1'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/message-filter-v0v1',
                '/pm/config/adom/{adom}/obj/gtp/message-filter-v0v1/{message-filter-v0v1}',
                '/pm/config/global/obj/gtp/message-filter-v0v1',
                '/pm/config/global/obj/gtp/message-filter-v0v1/{message-filter-v0v1}'
            ]
        },
        'gtp_messagefilterv2': {
            'params': ['adom', 'message-filter-v2'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/message-filter-v2',
                '/pm/config/adom/{adom}/obj/gtp/message-filter-v2/{message-filter-v2}',
                '/pm/config/global/obj/gtp/message-filter-v2',
                '/pm/config/global/obj/gtp/message-filter-v2/{message-filter-v2}'
            ]
        },
        'gtp_rattimeoutprofile': {
            'params': ['adom', 'rat-timeout-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/rat-timeout-profile',
                '/pm/config/adom/{adom}/obj/gtp/rat-timeout-profile/{rat-timeout-profile}',
                '/pm/config/global/obj/gtp/rat-timeout-profile',
                '/pm/config/global/obj/gtp/rat-timeout-profile/{rat-timeout-profile}'
            ],
            'v_range': [['7.4.7', '7.4.7']]
        },
        'gtp_tunnellimit': {
            'params': ['adom', 'tunnel-limit'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/tunnel-limit',
                '/pm/config/adom/{adom}/obj/gtp/tunnel-limit/{tunnel-limit}',
                '/pm/config/global/obj/gtp/tunnel-limit',
                '/pm/config/global/obj/gtp/tunnel-limit/{tunnel-limit}'
            ]
        },
        'header_consolidated_policy': {
            'params': ['adom', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/header/consolidated/policy',
                '/pm/config/adom/{adom}/obj/global/header/consolidated/policy/{policy}'
            ],
            'v_range': [['6.0.0', '7.0.4'], ['7.2.0', '7.2.1']]
        },
        'header_policy': {
            'params': ['adom', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/header/policy',
                '/pm/config/adom/{adom}/obj/global/header/policy/{policy}'
            ],
            'v_range': [['6.0.0', '7.0.4'], ['7.2.0', '7.2.1']]
        },
        'header_policy6': {
            'params': ['adom', 'policy6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/header/policy6',
                '/pm/config/adom/{adom}/obj/global/header/policy6/{policy6}'
            ],
            'v_range': [['6.0.0', '7.0.4'], ['7.2.0', '7.2.1']]
        },
        'header_policy6_identitybasedpolicy6': {
            'params': ['adom', 'identity-based-policy6', 'policy6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/header/policy6/{policy6}/identity-based-policy6',
                '/pm/config/adom/{adom}/obj/global/header/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'v_range': [['6.0.0', '6.2.0']]
        },
        'header_policy_identitybasedpolicy': {
            'params': ['adom', 'identity-based-policy', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/header/policy/{policy}/identity-based-policy',
                '/pm/config/adom/{adom}/obj/global/header/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'v_range': [['6.0.0', '6.2.0']]
        },
        'header_shapingpolicy': {
            'params': ['adom', 'shaping-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/header/shaping-policy',
                '/pm/config/adom/{adom}/obj/global/header/shaping-policy/{shaping-policy}'
            ],
            'v_range': [['6.0.0', '7.0.4'], ['7.2.0', '7.2.1']]
        },
        'hotspot20_anqp3gppcellular': {
            'params': ['adom', 'anqp-3gpp-cellular'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-3gpp-cellular',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}'
            ]
        },
        'hotspot20_anqp3gppcellular_mccmnclist': {
            'params': ['adom', 'anqp-3gpp-cellular', 'mcc-mnc-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}'
            ]
        },
        'hotspot20_anqpipaddresstype': {
            'params': ['adom', 'anqp-ip-address-type'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-ip-address-type',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-ip-address-type',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}'
            ]
        },
        'hotspot20_anqpnairealm': {
            'params': ['adom', 'anqp-nai-realm'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}'
            ]
        },
        'hotspot20_anqpnairealm_nailist': {
            'params': ['adom', 'anqp-nai-realm', 'nai-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}'
            ]
        },
        'hotspot20_anqpnairealm_nailist_eapmethod': {
            'params': ['adom', 'anqp-nai-realm', 'eap-method', 'nai-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}'
            ]
        },
        'hotspot20_anqpnairealm_nailist_eapmethod_authparam': {
            'params': ['adom', 'anqp-nai-realm', 'auth-param', 'eap-method', 'nai-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-pa'
                'ram',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-pa'
                'ram/{auth-param}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-param',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-param/{'
                'auth-param}'
            ]
        },
        'hotspot20_anqpnetworkauthtype': {
            'params': ['adom', 'anqp-network-auth-type'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-network-auth-type',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-network-auth-type',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}'
            ]
        },
        'hotspot20_anqproamingconsortium': {
            'params': ['adom', 'anqp-roaming-consortium'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-roaming-consortium',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}'
            ]
        },
        'hotspot20_anqproamingconsortium_oilist': {
            'params': ['adom', 'anqp-roaming-consortium', 'oi-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list/{oi-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list/{oi-list}'
            ]
        },
        'hotspot20_anqpvenuename': {
            'params': ['adom', 'anqp-venue-name'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-name',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}'
            ]
        },
        'hotspot20_anqpvenuename_valuelist': {
            'params': ['adom', 'anqp-venue-name', 'value-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list/{value-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list/{value-list}'
            ]
        },
        'hotspot20_anqpvenueurl': {
            'params': ['adom', 'anqp-venue-url'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-url',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-url',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'hotspot20_anqpvenueurl_valuelist': {
            'params': ['adom', 'anqp-venue-url', 'value-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list/{value-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list/{value-list}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qpadviceofcharge': {
            'params': ['adom', 'h2qp-advice-of-charge'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qpadviceofcharge_aoclist': {
            'params': ['adom', 'aoc-list', 'h2qp-advice-of-charge'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qpadviceofcharge_aoclist_planinfo': {
            'params': ['adom', 'aoc-list', 'h2qp-advice-of-charge', 'plan-info'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-info',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-info/{plan-i'
                'nfo}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-info',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-info/{plan-info}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qpconncapability': {
            'params': ['adom', 'h2qp-conn-capability'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-conn-capability',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-conn-capability',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}'
            ]
        },
        'hotspot20_h2qpoperatorname': {
            'params': ['adom', 'h2qp-operator-name'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-operator-name',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}'
            ]
        },
        'hotspot20_h2qpoperatorname_valuelist': {
            'params': ['adom', 'h2qp-operator-name', 'value-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list/{value-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list/{value-list}'
            ]
        },
        'hotspot20_h2qposuprovider': {
            'params': ['adom', 'h2qp-osu-provider'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}'
            ]
        },
        'hotspot20_h2qposuprovider_friendlyname': {
            'params': ['adom', 'friendly-name', 'h2qp-osu-provider'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}'
            ]
        },
        'hotspot20_h2qposuprovider_servicedescription': {
            'params': ['adom', 'h2qp-osu-provider', 'service-description'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-description}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-description}'
            ]
        },
        'hotspot20_h2qposuprovidernai': {
            'params': ['adom', 'h2qp-osu-provider-nai'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qposuprovidernai_nailist': {
            'params': ['adom', 'h2qp-osu-provider-nai', 'nai-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list/{nai-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list/{nai-list}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qptermsandconditions': {
            'params': ['adom', 'h2qp-terms-and-conditions'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-terms-and-conditions',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-terms-and-conditions/{h2qp-terms-and-conditions}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-terms-and-conditions',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-terms-and-conditions/{h2qp-terms-and-conditions}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qpwanmetric': {
            'params': ['adom', 'h2qp-wan-metric'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-wan-metric',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-wan-metric',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}'
            ]
        },
        'hotspot20_hsprofile': {
            'params': ['adom', 'hs-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/hs-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/hs-profile/{hs-profile}',
                '/pm/config/global/obj/wireless-controller/hotspot20/hs-profile',
                '/pm/config/global/obj/wireless-controller/hotspot20/hs-profile/{hs-profile}'
            ]
        },
        'hotspot20_icon': {
            'params': ['adom', 'icon'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/icon',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/icon/{icon}',
                '/pm/config/global/obj/wireless-controller/hotspot20/icon',
                '/pm/config/global/obj/wireless-controller/hotspot20/icon/{icon}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'hotspot20_icon_iconlist': {
            'params': ['adom', 'icon', 'icon-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/icon/{icon}/icon-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/icon/{icon}/icon-list/{icon-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/icon/{icon}/icon-list',
                '/pm/config/global/obj/wireless-controller/hotspot20/icon/{icon}/icon-list/{icon-list}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'hotspot20_qosmap': {
            'params': ['adom', 'qos-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}'
            ]
        },
        'hotspot20_qosmap_dscpexcept': {
            'params': ['adom', 'dscp-except', 'qos-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}'
            ]
        },
        'hotspot20_qosmap_dscprange': {
            'params': ['adom', 'dscp-range', 'qos-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range',
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}'
            ]
        },
        'icap_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/profile',
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}',
                '/pm/config/global/obj/icap/profile',
                '/pm/config/global/obj/icap/profile/{profile}'
            ]
        },
        'icap_profile_icapheaders': {
            'params': ['adom', 'icap-headers', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/icap-headers',
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/icap-headers/{icap-headers}',
                '/pm/config/global/obj/icap/profile/{profile}/icap-headers',
                '/pm/config/global/obj/icap/profile/{profile}/icap-headers/{icap-headers}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'icap_profile_respmodforwardrules': {
            'params': ['adom', 'profile', 'respmod-forward-rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/respmod-forward-rules',
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}',
                '/pm/config/global/obj/icap/profile/{profile}/respmod-forward-rules',
                '/pm/config/global/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'icap_profile_respmodforwardrules_headergroup': {
            'params': ['adom', 'header-group', 'profile', 'respmod-forward-rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}/header-group',
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}/header-group/{header-group}',
                '/pm/config/global/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}/header-group',
                '/pm/config/global/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}/header-group/{header-group}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'icap_server': {
            'params': ['adom', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/server',
                '/pm/config/adom/{adom}/obj/icap/server/{server}',
                '/pm/config/global/obj/icap/server',
                '/pm/config/global/obj/icap/server/{server}'
            ]
        },
        'icap_servergroup': {
            'params': ['adom', 'server-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/server-group',
                '/pm/config/adom/{adom}/obj/icap/server-group/{server-group}',
                '/pm/config/global/obj/icap/server-group',
                '/pm/config/global/obj/icap/server-group/{server-group}'
            ],
            'v_range': [['7.6.3', '']]
        },
        'icap_servergroup_serverlist': {
            'params': ['adom', 'server-group', 'server-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/server-group/{server-group}/server-list',
                '/pm/config/adom/{adom}/obj/icap/server-group/{server-group}/server-list/{server-list}',
                '/pm/config/global/obj/icap/server-group/{server-group}/server-list',
                '/pm/config/global/obj/icap/server-group/{server-group}/server-list/{server-list}'
            ],
            'v_range': [['7.6.3', '']]
        },
        'ips_baseline_sensor': {
            'params': ['adom', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor',
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}',
                '/pm/config/global/obj/ips/baseline/sensor',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}'
            ],
            'v_range': [['7.0.1', '7.0.2']]
        },
        'ips_baseline_sensor_entries': {
            'params': ['adom', 'entries', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/entries',
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/entries',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/entries/{entries}'
            ],
            'v_range': [['7.0.1', '7.0.2']]
        },
        'ips_baseline_sensor_entries_exemptip': {
            'params': ['adom', 'entries', 'exempt-ip', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/entries/{entries}/exempt-ip',
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/entries/{entries}/exempt-ip',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}'
            ],
            'v_range': [['7.0.1', '7.0.2']]
        },
        'ips_baseline_sensor_filter': {
            'params': ['adom', 'filter', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/filter',
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/filter',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/filter/{filter}'
            ],
            'v_range': [['7.0.1', '7.0.2']]
        },
        'ips_baseline_sensor_override': {
            'params': ['adom', 'override', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/override',
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/override/{override}',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/override',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/override/{override}'
            ],
            'v_range': [['7.0.1', '7.0.2']]
        },
        'ips_baseline_sensor_override_exemptip': {
            'params': ['adom', 'exempt-ip', 'override', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/override/{override}/exempt-ip',
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/override/{override}/exempt-ip',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}'
            ],
            'v_range': [['7.0.1', '7.0.2']]
        },
        'ips_custom': {
            'params': ['adom', 'custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/custom',
                '/pm/config/adom/{adom}/obj/ips/custom/{custom}',
                '/pm/config/global/obj/ips/custom',
                '/pm/config/global/obj/ips/custom/{custom}'
            ]
        },
        'ips_sensor': {
            'params': ['adom', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/ips/sensor',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}',
                '/pm/config/adom/{adom}/obj/ips/sensor',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}',
                '/pm/config/global/obj/global/ips/sensor',
                '/pm/config/global/obj/global/ips/sensor/{sensor}',
                '/pm/config/global/obj/ips/sensor',
                '/pm/config/global/obj/ips/sensor/{sensor}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'ips_sensor_entries': {
            'params': ['adom', 'entries', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/entries',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/entries',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries/{entries}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'ips_sensor_entries_exemptip': {
            'params': ['adom', 'entries', 'exempt-ip', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/entries/{entries}/exempt-ip',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}/exempt-ip',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/entries/{entries}/exempt-ip',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries/{entries}/exempt-ip',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'ips_sensor_filter': {
            'params': ['adom', 'filter', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/filter',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/filter',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/filter',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/ips/sensor/{sensor}/filter',
                '/pm/config/global/obj/ips/sensor/{sensor}/filter/{filter}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'ips_sensor_override': {
            'params': ['adom', 'override', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/override',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/override/{override}',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/override',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/override/{override}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/override',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/override/{override}',
                '/pm/config/global/obj/ips/sensor/{sensor}/override',
                '/pm/config/global/obj/ips/sensor/{sensor}/override/{override}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'ips_sensor_override_exemptip': {
            'params': ['adom', 'exempt-ip', 'override', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/override/{override}/exempt-ip',
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/override/{override}/exempt-ip',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/override/{override}/exempt-ip',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/sensor/{sensor}/override/{override}/exempt-ip',
                '/pm/config/global/obj/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'log_customfield': {
            'params': ['adom', 'custom-field'],
            'urls': [
                '/pm/config/adom/{adom}/obj/log/custom-field',
                '/pm/config/adom/{adom}/obj/log/custom-field/{custom-field}',
                '/pm/config/global/obj/log/custom-field',
                '/pm/config/global/obj/log/custom-field/{custom-field}'
            ]
        },
        'log_npuserver': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/log/npu-server',
                '/pm/config/global/obj/log/npu-server'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'log_npuserver_servergroup': {
            'params': ['adom', 'server-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/log/npu-server/server-group',
                '/pm/config/adom/{adom}/obj/log/npu-server/server-group/{server-group}',
                '/pm/config/global/obj/log/npu-server/server-group',
                '/pm/config/global/obj/log/npu-server/server-group/{server-group}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'log_npuserver_serverinfo': {
            'params': ['adom', 'server-info'],
            'urls': [
                '/pm/config/adom/{adom}/obj/log/npu-server/server-info',
                '/pm/config/adom/{adom}/obj/log/npu-server/server-info/{server-info}',
                '/pm/config/global/obj/log/npu-server/server-info',
                '/pm/config/global/obj/log/npu-server/server-info/{server-info}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'metafields_system_admin_user': {
            'params': [],
            'urls': [
                '/cli/global/_meta_fields/system/admin/user'
            ]
        },
        'mpskprofile': {
            'params': ['adom', 'mpsk-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}',
                '/pm/config/global/obj/wireless-controller/mpsk-profile',
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}'
            ],
            'v_range': [['6.4.2', '']]
        },
        'mpskprofile_mpskgroup': {
            'params': ['adom', 'mpsk-group', 'mpsk-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group',
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}',
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group',
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}'
            ],
            'v_range': [['6.4.2', '']]
        },
        'mpskprofile_mpskgroup_mpskkey': {
            'params': ['adom', 'mpsk-group', 'mpsk-key', 'mpsk-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key',
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}',
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key',
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}'
            ],
            'v_range': [['6.4.2', '']]
        },
        'nacprofile': {
            'params': ['adom', 'nac-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/nac-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/nac-profile/{nac-profile}',
                '/pm/config/global/obj/wireless-controller/nac-profile',
                '/pm/config/global/obj/wireless-controller/nac-profile/{nac-profile}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'pkg_authentication_rule': {
            'params': ['adom', 'pkg', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/authentication/rule',
                '/pm/config/adom/{adom}/pkg/{pkg}/authentication/rule/{rule}'
            ],
            'v_range': [['6.2.1', '']]
        },
        'pkg_authentication_setting': {
            'params': ['adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/authentication/setting'
            ],
            'v_range': [['6.2.1', '']]
        },
        'pkg_central_dnat': {
            'params': ['adom', 'dnat', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/central/dnat',
                '/pm/config/adom/{adom}/pkg/{pkg}/central/dnat/{dnat}'
            ]
        },
        'pkg_central_dnat6': {
            'params': ['adom', 'dnat6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/central/dnat6',
                '/pm/config/adom/{adom}/pkg/{pkg}/central/dnat6/{dnat6}'
            ],
            'v_range': [['6.4.2', '']]
        },
        'pkg_firewall_acl': {
            'params': ['acl', 'adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl/{acl}'
            ],
            'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_acl6': {
            'params': ['acl6', 'adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl6',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl6/{acl6}'
            ],
            'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_centralsnatmap': {
            'params': ['adom', 'central-snat-map', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/central-snat-map',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/central-snat-map/{central-snat-map}'
            ]
        },
        'pkg_firewall_consolidated_policy': {
            'params': ['adom', 'pkg', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/consolidated/policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/consolidated/policy/{policy}'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'pkg_firewall_dospolicy': {
            'params': ['DoS-policy', 'adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy/{DoS-policy}'
            ]
        },
        'pkg_firewall_dospolicy6': {
            'params': ['DoS-policy6', 'adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6/{DoS-policy6}'
            ]
        },
        'pkg_firewall_dospolicy6_anomaly': {
            'params': ['DoS-policy6', 'adom', 'anomaly', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6/{DoS-policy6}/anomaly',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6/{DoS-policy6}/anomaly/{anomaly}'
            ]
        },
        'pkg_firewall_dospolicy_anomaly': {
            'params': ['DoS-policy', 'adom', 'anomaly', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy/{DoS-policy}/anomaly',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy/{DoS-policy}/anomaly/{anomaly}'
            ]
        },
        'pkg_firewall_explicitproxypolicy': {
            'params': ['adom', 'explicit-proxy-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/explicit-proxy-policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/explicit-proxy-policy/{explicit-proxy-policy}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'pkg_firewall_explicitproxypolicy_identitybasedpolicy': {
            'params': ['adom', 'explicit-proxy-policy', 'identity-based-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/explicit-proxy-policy/{explicit-proxy-policy}/identity-based-policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/explicit-proxy-policy/{explicit-proxy-policy}/identity-based-policy/{identity-based-policy}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'pkg_firewall_hyperscalepolicy': {
            'params': ['adom', 'hyperscale-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy/{hyperscale-policy}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_hyperscalepolicy46': {
            'params': ['adom', 'hyperscale-policy46', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy46',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy46/{hyperscale-policy46}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_hyperscalepolicy6': {
            'params': ['adom', 'hyperscale-policy6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy6',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy6/{hyperscale-policy6}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']]
        },
        'pkg_firewall_hyperscalepolicy64': {
            'params': ['adom', 'hyperscale-policy64', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy64',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy64/{hyperscale-policy64}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_interfacepolicy': {
            'params': ['adom', 'interface-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy/{interface-policy}'
            ],
            'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_interfacepolicy6': {
            'params': ['adom', 'interface-policy6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy6',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy6/{interface-policy6}'
            ],
            'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_localinpolicy': {
            'params': ['adom', 'local-in-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy/{local-in-policy}'
            ]
        },
        'pkg_firewall_localinpolicy6': {
            'params': ['adom', 'local-in-policy6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy6',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy6/{local-in-policy6}'
            ]
        },
        'pkg_firewall_multicastpolicy': {
            'params': ['adom', 'multicast-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy/{multicast-policy}'
            ]
        },
        'pkg_firewall_multicastpolicy6': {
            'params': ['adom', 'multicast-policy6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy6',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy6/{multicast-policy6}'
            ]
        },
        'pkg_firewall_policy': {
            'params': ['adom', 'pkg', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}'
            ]
        },
        'pkg_firewall_policy46': {
            'params': ['adom', 'pkg', 'policy46'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy46',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy46/{policy46}'
            ]
        },
        'pkg_firewall_policy6': {
            'params': ['adom', 'pkg', 'policy6'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy6',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy6/{policy6}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'pkg_firewall_policy64': {
            'params': ['adom', 'pkg', 'policy64'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy64',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy64/{policy64}'
            ]
        },
        'pkg_firewall_policy_vpndstnode': {
            'params': ['adom', 'pkg', 'policy', 'vpn_dst_node'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/vpn_dst_node',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/vpn_dst_node/{vpn_dst_node}'
            ],
            'v_range': [['6.0.0', '7.0.2']]
        },
        'pkg_firewall_policy_vpnsrcnode': {
            'params': ['adom', 'pkg', 'policy', 'vpn_src_node'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/vpn_src_node',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/vpn_src_node/{vpn_src_node}'
            ],
            'v_range': [['6.0.0', '7.0.2']]
        },
        'pkg_firewall_proxypolicy': {
            'params': ['adom', 'pkg', 'proxy-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/proxy-policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/proxy-policy/{proxy-policy}'
            ]
        },
        'pkg_firewall_securitypolicy': {
            'params': ['adom', 'pkg', 'security-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/security-policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/security-policy/{security-policy}'
            ],
            'v_range': [['6.2.1', '']]
        },
        'pkg_firewall_shapingpolicy': {
            'params': ['adom', 'pkg', 'shaping-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/shaping-policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/shaping-policy/{shaping-policy}'
            ]
        },
        'pkg_footer_consolidated_policy': {
            'params': ['adom', 'pkg', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/global/footer/consolidated/policy/{policy}',
                '/pm/config/global/pkg/{pkg}/global/footer/consolidated/policy',
                '/pm/config/global/pkg/{pkg}/global/footer/consolidated/policy/{policy}'
            ],
            'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '7.6.2']]
        },
        'pkg_footer_policy': {
            'params': ['adom', 'pkg', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/global/footer/policy/{policy}',
                '/pm/config/global/pkg/{pkg}/global/footer/policy',
                '/pm/config/global/pkg/{pkg}/global/footer/policy/{policy}'
            ],
            'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']]
        },
        'pkg_footer_policy6': {
            'params': ['adom', 'pkg', 'policy6'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/global/footer/policy6/{policy6}',
                '/pm/config/global/pkg/{pkg}/global/footer/policy6',
                '/pm/config/global/pkg/{pkg}/global/footer/policy6/{policy6}'
            ],
            'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']]
        },
        'pkg_footer_policy6_identitybasedpolicy6': {
            'params': ['identity-based-policy6', 'pkg', 'policy6'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy6/{policy6}/identity-based-policy6',
                '/pm/config/global/pkg/{pkg}/global/footer/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'v_range': [['6.0.0', '6.2.0']]
        },
        'pkg_footer_policy_identitybasedpolicy': {
            'params': ['identity-based-policy', 'pkg', 'policy'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy/{policy}/identity-based-policy',
                '/pm/config/global/pkg/{pkg}/global/footer/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'v_range': [['6.0.0', '6.2.0']]
        },
        'pkg_footer_shapingpolicy': {
            'params': ['adom', 'pkg', 'shaping-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/global/footer/shaping-policy/{shaping-policy}',
                '/pm/config/global/pkg/{pkg}/global/footer/shaping-policy',
                '/pm/config/global/pkg/{pkg}/global/footer/shaping-policy/{shaping-policy}'
            ],
            'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']]
        },
        'pkg_header_consolidated_policy': {
            'params': ['adom', 'pkg', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/global/header/consolidated/policy/{policy}',
                '/pm/config/global/pkg/{pkg}/global/header/consolidated/policy',
                '/pm/config/global/pkg/{pkg}/global/header/consolidated/policy/{policy}'
            ],
            'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '7.6.2']]
        },
        'pkg_header_policy': {
            'params': ['adom', 'pkg', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/global/header/policy/{policy}',
                '/pm/config/global/pkg/{pkg}/global/header/policy',
                '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}'
            ],
            'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']]
        },
        'pkg_header_policy6': {
            'params': ['adom', 'pkg', 'policy6'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/global/header/policy6/{policy6}',
                '/pm/config/global/pkg/{pkg}/global/header/policy6',
                '/pm/config/global/pkg/{pkg}/global/header/policy6/{policy6}'
            ],
            'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']]
        },
        'pkg_header_policy6_identitybasedpolicy6': {
            'params': ['identity-based-policy6', 'pkg', 'policy6'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy6/{policy6}/identity-based-policy6',
                '/pm/config/global/pkg/{pkg}/global/header/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'v_range': [['6.0.0', '6.2.0']]
        },
        'pkg_header_policy_identitybasedpolicy': {
            'params': ['identity-based-policy', 'pkg', 'policy'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}/identity-based-policy',
                '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'v_range': [['6.0.0', '6.2.0']]
        },
        'pkg_header_shapingpolicy': {
            'params': ['adom', 'pkg', 'shaping-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/global/header/shaping-policy/{shaping-policy}',
                '/pm/config/global/pkg/{pkg}/global/header/shaping-policy',
                '/pm/config/global/pkg/{pkg}/global/header/shaping-policy/{shaping-policy}'
            ],
            'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']]
        },
        'pkg_user_nacpolicy': {
            'params': ['adom', 'nac-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/user/nac-policy',
                '/pm/config/adom/{adom}/pkg/{pkg}/user/nac-policy/{nac-policy}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'pkg_videofilter_youtubekey': {
            'params': ['adom', 'pkg', 'youtube-key'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/videofilter/youtube-key',
                '/pm/config/adom/{adom}/pkg/{pkg}/videofilter/youtube-key/{youtube-key}'
            ],
            'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']]
        },
        'pm_config_adom_options': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/_adom/options'
            ],
            'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'pm_config_application_list': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/_application/list',
                '/pm/config/global/_application/list'
            ],
            'v_range': [['6.2.0', '']]
        },
        'pm_config_category_list': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/_category/list',
                '/pm/config/global/_category/list'
            ],
            'v_range': [['6.2.0', '']]
        },
        'pm_config_data_defaultsslvpnoschecklist': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/_data/default_sslvpn_os_check_list',
                '/pm/config/global/_data/default_sslvpn_os_check_list'
            ],
            'v_range': [['7.2.5', '7.2.11'], ['7.4.3', '']]
        },
        'pm_config_data_tablesize': {
            'params': ['adom', 'tablesize'],
            'urls': [
                '/pm/config/adom/{adom}/_data/tablesize',
                '/pm/config/adom/{adom}/_data/tablesize/{tablesize}',
                '/pm/config/global/_data/tablesize',
                '/pm/config/global/_data/tablesize/{tablesize}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'pm_config_data_tablesize_faz': {
            'params': ['adom', 'faz'],
            'urls': [
                '/pm/config/adom/{adom}/_data/tablesize/faz',
                '/pm/config/adom/{adom}/_data/tablesize/faz/{faz}',
                '/pm/config/global/_data/tablesize/faz',
                '/pm/config/global/_data/tablesize/faz/{faz}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'pm_config_data_tablesize_fmg': {
            'params': ['adom', 'fmg'],
            'urls': [
                '/pm/config/adom/{adom}/_data/tablesize/fmg',
                '/pm/config/adom/{adom}/_data/tablesize/fmg/{fmg}',
                '/pm/config/global/_data/tablesize/fmg',
                '/pm/config/global/_data/tablesize/fmg/{fmg}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'pm_config_data_tablesize_fos': {
            'params': ['adom', 'fos'],
            'urls': [
                '/pm/config/adom/{adom}/_data/tablesize/fos',
                '/pm/config/adom/{adom}/_data/tablesize/fos/{fos}',
                '/pm/config/global/_data/tablesize/fos',
                '/pm/config/global/_data/tablesize/fos/{fos}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'pm_config_data_tablesize_log': {
            'params': ['adom', 'log'],
            'urls': [
                '/pm/config/adom/{adom}/_data/tablesize/log',
                '/pm/config/adom/{adom}/_data/tablesize/log/{log}',
                '/pm/config/global/_data/tablesize/log',
                '/pm/config/global/_data/tablesize/log/{log}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'pm_config_fct_endpointcontrol_profile': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/_fct/endpoint-control/profile'
            ],
            'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '7.4.1']]
        },
        'pm_config_metafields_firewall_address': {
            'params': [],
            'urls': [
                '/pm/config/_meta_fields/firewall/address'
            ],
            'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'pm_config_metafields_firewall_addrgrp': {
            'params': [],
            'urls': [
                '/pm/config/_meta_fields/firewall/addrgrp'
            ],
            'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'pm_config_metafields_firewall_centralsnatmap': {
            'params': [],
            'urls': [
                '/pm/config/_meta_fields/firewall/central-snat-map'
            ],
            'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'pm_config_metafields_firewall_policy': {
            'params': [],
            'urls': [
                '/pm/config/_meta_fields/firewall/policy'
            ],
            'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'pm_config_metafields_firewall_service_custom': {
            'params': [],
            'urls': [
                '/pm/config/_meta_fields/firewall/service/custom'
            ],
            'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'pm_config_metafields_firewall_service_group': {
            'params': [],
            'urls': [
                '/pm/config/_meta_fields/firewall/service/group'
            ],
            'v_range': [['6.2.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'pm_config_package_status': {
            'params': ['adom', 'device_name', 'vdom_name'],
            'urls': [
                '/pm/config/adom/{adom}/_package/status',
                '/pm/config/adom/{adom}/_package/status/{device_name}/{vdom_name}',
                '/pm/config/global/_package/status'
            ],
            'v_range': [['7.0.7', '7.0.14'], ['7.2.2', '']]
        },
        'pm_config_pblock_firewall_consolidated_policy': {
            'params': ['adom', 'pblock', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/consolidated/policy',
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/consolidated/policy/{policy}'
            ],
            'v_range': [['7.0.3', '7.6.2']]
        },
        'pm_config_pblock_firewall_policy': {
            'params': ['adom', 'pblock', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy',
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy/{policy}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'pm_config_pblock_firewall_policy6': {
            'params': ['adom', 'pblock', 'policy6'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy6',
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy6/{policy6}'
            ],
            'v_range': [['7.0.3', '7.6.2']]
        },
        'pm_config_pblock_firewall_proxypolicy': {
            'params': ['adom', 'pblock', 'proxy-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/proxy-policy',
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/proxy-policy/{proxy-policy}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'pm_config_pblock_firewall_securitypolicy': {
            'params': ['adom', 'pblock', 'security-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/security-policy',
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/security-policy/{security-policy}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'pm_config_rule_list': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/_rule/list',
                '/pm/config/global/_rule/list'
            ],
            'v_range': [['6.2.0', '']]
        },
        'pm_devprof': {
            'params': ['adom', 'pkg_path'],
            'urls': [
                '/pm/devprof/adom/{adom}/{pkg_path}'
            ]
        },
        'pm_devprof_adom': {
            'params': ['adom'],
            'urls': [
                '/pm/devprof/adom/{adom}'
            ]
        },
        'pm_pblock': {
            'params': ['adom', 'pkg_path'],
            'urls': [
                '/pm/pblock/adom/{adom}/{pkg_path}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'pm_pblock_adom': {
            'params': ['adom'],
            'urls': [
                '/pm/pblock/adom/{adom}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'pm_pkg': {
            'params': ['adom', 'pkg_path'],
            'urls': [
                '/pm/pkg/adom/{adom}/{pkg_path}',
                '/pm/pkg/global/{pkg_path}'
            ]
        },
        'pm_pkg_adom': {
            'params': ['adom'],
            'urls': [
                '/pm/pkg/adom/{adom}'
            ]
        },
        'pm_pkg_global': {
            'params': [],
            'urls': [
                '/pm/pkg/global'
            ]
        },
        'pm_pkg_schedule': {
            'params': ['adom', 'pkg_name_path'],
            'urls': [
                '/pm/pkg/adom/{adom}/{pkg_name_path}/schedule',
                '/pm/pkg/global/{pkg_name_path}/schedule'
            ]
        },
        'pm_wanprof': {
            'params': ['adom', 'pkg_path'],
            'urls': [
                '/pm/wanprof/adom/{adom}/{pkg_path}'
            ]
        },
        'pm_wanprof_adom': {
            'params': ['adom'],
            'urls': [
                '/pm/wanprof/adom/{adom}'
            ]
        },
        'qosprofile': {
            'params': ['adom', 'qos-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/qos-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/qos-profile/{qos-profile}',
                '/pm/config/global/obj/wireless-controller/qos-profile',
                '/pm/config/global/obj/wireless-controller/qos-profile/{qos-profile}'
            ]
        },
        'region': {
            'params': ['adom', 'region'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/region',
                '/pm/config/adom/{adom}/obj/wireless-controller/region/{region}',
                '/pm/config/global/obj/wireless-controller/region',
                '/pm/config/global/obj/wireless-controller/region/{region}'
            ],
            'v_range': [['6.2.8', '6.2.13'], ['6.4.6', '']]
        },
        'router_accesslist': {
            'params': ['access-list', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/access-list',
                '/pm/config/adom/{adom}/obj/router/access-list/{access-list}',
                '/pm/config/global/obj/router/access-list',
                '/pm/config/global/obj/router/access-list/{access-list}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_accesslist6': {
            'params': ['access-list6', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/access-list6',
                '/pm/config/adom/{adom}/obj/router/access-list6/{access-list6}',
                '/pm/config/global/obj/router/access-list6',
                '/pm/config/global/obj/router/access-list6/{access-list6}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_accesslist6_rule': {
            'params': ['access-list6', 'adom', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/access-list6/{access-list6}/rule',
                '/pm/config/adom/{adom}/obj/router/access-list6/{access-list6}/rule/{rule}',
                '/pm/config/global/obj/router/access-list6/{access-list6}/rule',
                '/pm/config/global/obj/router/access-list6/{access-list6}/rule/{rule}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_accesslist_rule': {
            'params': ['access-list', 'adom', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/access-list/{access-list}/rule',
                '/pm/config/adom/{adom}/obj/router/access-list/{access-list}/rule/{rule}',
                '/pm/config/global/obj/router/access-list/{access-list}/rule',
                '/pm/config/global/obj/router/access-list/{access-list}/rule/{rule}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_aspathlist': {
            'params': ['adom', 'aspath-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/aspath-list',
                '/pm/config/adom/{adom}/obj/router/aspath-list/{aspath-list}',
                '/pm/config/global/obj/router/aspath-list',
                '/pm/config/global/obj/router/aspath-list/{aspath-list}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_aspathlist_rule': {
            'params': ['adom', 'aspath-list', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/aspath-list/{aspath-list}/rule',
                '/pm/config/adom/{adom}/obj/router/aspath-list/{aspath-list}/rule/{rule}',
                '/pm/config/global/obj/router/aspath-list/{aspath-list}/rule',
                '/pm/config/global/obj/router/aspath-list/{aspath-list}/rule/{rule}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_communitylist': {
            'params': ['adom', 'community-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/community-list',
                '/pm/config/adom/{adom}/obj/router/community-list/{community-list}',
                '/pm/config/global/obj/router/community-list',
                '/pm/config/global/obj/router/community-list/{community-list}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_communitylist_rule': {
            'params': ['adom', 'community-list', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/community-list/{community-list}/rule',
                '/pm/config/adom/{adom}/obj/router/community-list/{community-list}/rule/{rule}',
                '/pm/config/global/obj/router/community-list/{community-list}/rule',
                '/pm/config/global/obj/router/community-list/{community-list}/rule/{rule}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_prefixlist': {
            'params': ['adom', 'prefix-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/prefix-list',
                '/pm/config/adom/{adom}/obj/router/prefix-list/{prefix-list}',
                '/pm/config/global/obj/router/prefix-list',
                '/pm/config/global/obj/router/prefix-list/{prefix-list}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_prefixlist6': {
            'params': ['adom', 'prefix-list6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/prefix-list6',
                '/pm/config/adom/{adom}/obj/router/prefix-list6/{prefix-list6}',
                '/pm/config/global/obj/router/prefix-list6',
                '/pm/config/global/obj/router/prefix-list6/{prefix-list6}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_prefixlist6_rule': {
            'params': ['adom', 'prefix-list6', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/prefix-list6/{prefix-list6}/rule',
                '/pm/config/adom/{adom}/obj/router/prefix-list6/{prefix-list6}/rule/{rule}',
                '/pm/config/global/obj/router/prefix-list6/{prefix-list6}/rule',
                '/pm/config/global/obj/router/prefix-list6/{prefix-list6}/rule/{rule}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_prefixlist_rule': {
            'params': ['adom', 'prefix-list', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/prefix-list/{prefix-list}/rule',
                '/pm/config/adom/{adom}/obj/router/prefix-list/{prefix-list}/rule/{rule}',
                '/pm/config/global/obj/router/prefix-list/{prefix-list}/rule',
                '/pm/config/global/obj/router/prefix-list/{prefix-list}/rule/{rule}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_routemap': {
            'params': ['adom', 'route-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/route-map',
                '/pm/config/adom/{adom}/obj/router/route-map/{route-map}',
                '/pm/config/global/obj/router/route-map',
                '/pm/config/global/obj/router/route-map/{route-map}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'router_routemap_rule': {
            'params': ['adom', 'route-map', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/route-map/{route-map}/rule',
                '/pm/config/adom/{adom}/obj/router/route-map/{route-map}/rule/{rule}',
                '/pm/config/global/obj/router/route-map/{route-map}/rule',
                '/pm/config/global/obj/router/route-map/{route-map}/rule/{rule}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'sctpfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/sctp-filter/profile',
                '/pm/config/adom/{adom}/obj/sctp-filter/profile/{profile}',
                '/pm/config/global/obj/sctp-filter/profile',
                '/pm/config/global/obj/sctp-filter/profile/{profile}'
            ],
            'v_range': [['7.2.5', '7.2.11'], ['7.4.2', '']]
        },
        'sctpfilter_profile_ppidfilters': {
            'params': ['adom', 'ppid-filters', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/sctp-filter/profile/{profile}/ppid-filters',
                '/pm/config/adom/{adom}/obj/sctp-filter/profile/{profile}/ppid-filters/{ppid-filters}',
                '/pm/config/global/obj/sctp-filter/profile/{profile}/ppid-filters',
                '/pm/config/global/obj/sctp-filter/profile/{profile}/ppid-filters/{ppid-filters}'
            ],
            'v_range': [['7.2.5', '7.2.11'], ['7.4.2', '']]
        },
        'spamfilter_bwl': {
            'params': ['adom', 'bwl'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bwl',
                '/pm/config/adom/{adom}/obj/spamfilter/bwl/{bwl}',
                '/pm/config/global/obj/spamfilter/bwl',
                '/pm/config/global/obj/spamfilter/bwl/{bwl}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_bwl_entries': {
            'params': ['adom', 'bwl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bwl/{bwl}/entries',
                '/pm/config/adom/{adom}/obj/spamfilter/bwl/{bwl}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/bwl/{bwl}/entries',
                '/pm/config/global/obj/spamfilter/bwl/{bwl}/entries/{entries}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_bword': {
            'params': ['adom', 'bword'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bword',
                '/pm/config/adom/{adom}/obj/spamfilter/bword/{bword}',
                '/pm/config/global/obj/spamfilter/bword',
                '/pm/config/global/obj/spamfilter/bword/{bword}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_bword_entries': {
            'params': ['adom', 'bword', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bword/{bword}/entries',
                '/pm/config/adom/{adom}/obj/spamfilter/bword/{bword}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/bword/{bword}/entries',
                '/pm/config/global/obj/spamfilter/bword/{bword}/entries/{entries}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_dnsbl': {
            'params': ['adom', 'dnsbl'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/dnsbl',
                '/pm/config/adom/{adom}/obj/spamfilter/dnsbl/{dnsbl}',
                '/pm/config/global/obj/spamfilter/dnsbl',
                '/pm/config/global/obj/spamfilter/dnsbl/{dnsbl}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_dnsbl_entries': {
            'params': ['adom', 'dnsbl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/dnsbl/{dnsbl}/entries',
                '/pm/config/adom/{adom}/obj/spamfilter/dnsbl/{dnsbl}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/dnsbl/{dnsbl}/entries',
                '/pm/config/global/obj/spamfilter/dnsbl/{dnsbl}/entries/{entries}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_iptrust': {
            'params': ['adom', 'iptrust'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/iptrust',
                '/pm/config/adom/{adom}/obj/spamfilter/iptrust/{iptrust}',
                '/pm/config/global/obj/spamfilter/iptrust',
                '/pm/config/global/obj/spamfilter/iptrust/{iptrust}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_iptrust_entries': {
            'params': ['adom', 'entries', 'iptrust'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/iptrust/{iptrust}/entries',
                '/pm/config/adom/{adom}/obj/spamfilter/iptrust/{iptrust}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/iptrust/{iptrust}/entries',
                '/pm/config/global/obj/spamfilter/iptrust/{iptrust}/entries/{entries}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_mheader': {
            'params': ['adom', 'mheader'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/mheader',
                '/pm/config/adom/{adom}/obj/spamfilter/mheader/{mheader}',
                '/pm/config/global/obj/spamfilter/mheader',
                '/pm/config/global/obj/spamfilter/mheader/{mheader}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_mheader_entries': {
            'params': ['adom', 'entries', 'mheader'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/mheader/{mheader}/entries',
                '/pm/config/adom/{adom}/obj/spamfilter/mheader/{mheader}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/mheader/{mheader}/entries',
                '/pm/config/global/obj/spamfilter/mheader/{mheader}/entries/{entries}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile',
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}',
                '/pm/config/global/obj/spamfilter/profile',
                '/pm/config/global/obj/spamfilter/profile/{profile}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_profile_gmail': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/gmail',
                '/pm/config/global/obj/spamfilter/profile/{profile}/gmail'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_profile_imap': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/imap',
                '/pm/config/global/obj/spamfilter/profile/{profile}/imap'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_profile_mapi': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/mapi',
                '/pm/config/global/obj/spamfilter/profile/{profile}/mapi'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_profile_msnhotmail': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/msn-hotmail',
                '/pm/config/global/obj/spamfilter/profile/{profile}/msn-hotmail'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_profile_pop3': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/pop3',
                '/pm/config/global/obj/spamfilter/profile/{profile}/pop3'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_profile_smtp': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/smtp',
                '/pm/config/global/obj/spamfilter/profile/{profile}/smtp'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_profile_yahoomail': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}/yahoo-mail',
                '/pm/config/global/obj/spamfilter/profile/{profile}/yahoo-mail'
            ],
            'v_range': [['6.0.0', '6.2.13']]
        },
        'sshfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile',
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}',
                '/pm/config/global/obj/ssh-filter/profile',
                '/pm/config/global/obj/ssh-filter/profile/{profile}'
            ]
        },
        'sshfilter_profile_filefilter': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/file-filter',
                '/pm/config/global/obj/ssh-filter/profile/{profile}/file-filter'
            ],
            'v_range': [['6.2.2', '7.6.2']]
        },
        'sshfilter_profile_filefilter_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/file-filter/entries',
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/global/obj/ssh-filter/profile/{profile}/file-filter/entries',
                '/pm/config/global/obj/ssh-filter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'v_range': [['6.2.2', '7.6.2']]
        },
        'sshfilter_profile_shellcommands': {
            'params': ['adom', 'profile', 'shell-commands'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/shell-commands',
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/shell-commands/{shell-commands}',
                '/pm/config/global/obj/ssh-filter/profile/{profile}/shell-commands',
                '/pm/config/global/obj/ssh-filter/profile/{profile}/shell-commands/{shell-commands}'
            ]
        },
        'switchcontroller_acl_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/acl/group',
                '/pm/config/adom/{adom}/obj/switch-controller/acl/group/{group}',
                '/pm/config/global/obj/switch-controller/acl/group',
                '/pm/config/global/obj/switch-controller/acl/group/{group}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'switchcontroller_acl_ingress': {
            'params': ['adom', 'ingress'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/acl/ingress',
                '/pm/config/adom/{adom}/obj/switch-controller/acl/ingress/{ingress}',
                '/pm/config/global/obj/switch-controller/acl/ingress',
                '/pm/config/global/obj/switch-controller/acl/ingress/{ingress}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'switchcontroller_acl_ingress_action': {
            'params': ['adom', 'ingress'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/acl/ingress/{ingress}/action',
                '/pm/config/global/obj/switch-controller/acl/ingress/{ingress}/action'
            ],
            'v_range': [['7.4.0', '']]
        },
        'switchcontroller_acl_ingress_classifier': {
            'params': ['adom', 'ingress'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/acl/ingress/{ingress}/classifier',
                '/pm/config/global/obj/switch-controller/acl/ingress/{ingress}/classifier'
            ],
            'v_range': [['7.4.0', '']]
        },
        'switchcontroller_customcommand': {
            'params': ['adom', 'custom-command'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/custom-command',
                '/pm/config/adom/{adom}/obj/switch-controller/custom-command/{custom-command}',
                '/pm/config/global/obj/switch-controller/custom-command',
                '/pm/config/global/obj/switch-controller/custom-command/{custom-command}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'switchcontroller_dsl_policy': {
            'params': ['adom', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/dsl/policy',
                '/pm/config/adom/{adom}/obj/switch-controller/dsl/policy/{policy}',
                '/pm/config/global/obj/switch-controller/dsl/policy',
                '/pm/config/global/obj/switch-controller/dsl/policy/{policy}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'switchcontroller_dynamicportpolicy': {
            'params': ['adom', 'dynamic-port-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/dynamic-port-policy',
                '/pm/config/adom/{adom}/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}',
                '/pm/config/global/obj/switch-controller/dynamic-port-policy',
                '/pm/config/global/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'switchcontroller_dynamicportpolicy_policy': {
            'params': ['adom', 'dynamic-port-policy', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy',
                '/pm/config/adom/{adom}/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}',
                '/pm/config/global/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy',
                '/pm/config/global/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'switchcontroller_fortilinksettings': {
            'params': ['adom', 'fortilink-settings'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/fortilink-settings',
                '/pm/config/adom/{adom}/obj/switch-controller/fortilink-settings/{fortilink-settings}',
                '/pm/config/global/obj/switch-controller/fortilink-settings',
                '/pm/config/global/obj/switch-controller/fortilink-settings/{fortilink-settings}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'switchcontroller_fortilinksettings_nacports': {
            'params': ['adom', 'fortilink-settings'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/fortilink-settings/{fortilink-settings}/nac-ports',
                '/pm/config/global/obj/switch-controller/fortilink-settings/{fortilink-settings}/nac-ports'
            ],
            'v_range': [['7.2.1', '']]
        },
        'switchcontroller_lldpprofile': {
            'params': ['adom', 'lldp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile',
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}',
                '/pm/config/global/obj/switch-controller/lldp-profile',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}'
            ]
        },
        'switchcontroller_lldpprofile_customtlvs': {
            'params': ['adom', 'custom-tlvs', 'lldp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs',
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}'
            ]
        },
        'switchcontroller_lldpprofile_medlocationservice': {
            'params': ['adom', 'lldp-profile', 'med-location-service'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/med-location-service',
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/med-location-service/{med-location-service}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/med-location-service',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/med-location-service/{med-location-service}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'switchcontroller_lldpprofile_mednetworkpolicy': {
            'params': ['adom', 'lldp-profile', 'med-network-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/med-network-policy',
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/med-network-policy',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}'
            ]
        },
        'switchcontroller_macpolicy': {
            'params': ['adom', 'mac-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/mac-policy',
                '/pm/config/adom/{adom}/obj/switch-controller/mac-policy/{mac-policy}',
                '/pm/config/global/obj/switch-controller/mac-policy',
                '/pm/config/global/obj/switch-controller/mac-policy/{mac-policy}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'switchcontroller_managedswitch': {
            'params': ['adom', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}',
                '/pm/config/global/obj/switch-controller/managed-switch',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}'
            ]
        },
        'switchcontroller_managedswitch_customcommand': {
            'params': ['adom', 'custom-command', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/custom-command',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/custom-command/{custom-command}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/custom-command',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/custom-command/{custom-command}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'switchcontroller_managedswitch_dhcpsnoopingstaticclient': {
            'params': ['adom', 'dhcp-snooping-static-client', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/dhcp-snooping-static-client',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/dhcp-snooping-static-client/{dhcp-snooping-static-client}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/dhcp-snooping-static-client',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/dhcp-snooping-static-client/{dhcp-snooping-static-client}'
            ],
            'v_range': [['7.2.2', '']]
        },
        'switchcontroller_managedswitch_ipsourceguard': {
            'params': ['adom', 'ip-source-guard', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}'
            ],
            'v_range': [['6.4.0', '6.4.1']]
        },
        'switchcontroller_managedswitch_ipsourceguard_bindingentry': {
            'params': ['adom', 'binding-entry', 'ip-source-guard', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry/{binding-entry}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry/{binding-entry}'
            ],
            'v_range': [['6.4.0', '6.4.1']]
        },
        'switchcontroller_managedswitch_ports': {
            'params': ['adom', 'managed-switch', 'ports'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ports',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ports',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}'
            ]
        },
        'switchcontroller_managedswitch_ports_dhcpsnoopoption82override': {
            'params': ['adom', 'dhcp-snoop-option82-override', 'managed-switch', 'ports'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}/dhcp-snoop-option82-override',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}/dhcp-snoop-option82-override/{dhcp-snoop-option82'
                '-override}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}/dhcp-snoop-option82-override',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}/dhcp-snoop-option82-override/{dhcp-snoop-option82-over'
                'ride}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'switchcontroller_managedswitch_remotelog': {
            'params': ['adom', 'managed-switch', 'remote-log'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/remote-log',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/remote-log/{remote-log}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/remote-log',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/remote-log/{remote-log}'
            ],
            'v_range': [['6.2.1', '6.2.3']]
        },
        'switchcontroller_managedswitch_routeoffloadrouter': {
            'params': ['adom', 'managed-switch', 'route-offload-router'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/route-offload-router',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/route-offload-router/{route-offload-router}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/route-offload-router',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/route-offload-router/{route-offload-router}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'switchcontroller_managedswitch_snmpcommunity': {
            'params': ['adom', 'managed-switch', 'snmp-community'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-community',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-community',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}'
            ],
            'v_range': [['6.2.1', '6.2.3']]
        },
        'switchcontroller_managedswitch_snmpcommunity_hosts': {
            'params': ['adom', 'hosts', 'managed-switch', 'snmp-community'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts/{hosts}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts/{hosts}'
            ],
            'v_range': [['6.2.1', '6.2.3']]
        },
        'switchcontroller_managedswitch_snmpsysinfo': {
            'params': ['adom', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-sysinfo',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-sysinfo'
            ],
            'v_range': [['6.2.1', '6.2.3']]
        },
        'switchcontroller_managedswitch_snmptrapthreshold': {
            'params': ['adom', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-trap-threshold',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-trap-threshold'
            ],
            'v_range': [['6.2.1', '6.2.3']]
        },
        'switchcontroller_managedswitch_snmpuser': {
            'params': ['adom', 'managed-switch', 'snmp-user'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-user',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-user/{snmp-user}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-user',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-user/{snmp-user}'
            ],
            'v_range': [['6.2.1', '6.2.3']]
        },
        'switchcontroller_managedswitch_vlan': {
            'params': ['adom', 'managed-switch', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/vlan',
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/vlan/{vlan}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/vlan',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/vlan/{vlan}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'switchcontroller_ptp_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/ptp/profile',
                '/pm/config/adom/{adom}/obj/switch-controller/ptp/profile/{profile}',
                '/pm/config/global/obj/switch-controller/ptp/profile',
                '/pm/config/global/obj/switch-controller/ptp/profile/{profile}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'switchcontroller_qos_dot1pmap': {
            'params': ['adom', 'dot1p-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/dot1p-map',
                '/pm/config/adom/{adom}/obj/switch-controller/qos/dot1p-map/{dot1p-map}',
                '/pm/config/global/obj/switch-controller/qos/dot1p-map',
                '/pm/config/global/obj/switch-controller/qos/dot1p-map/{dot1p-map}'
            ]
        },
        'switchcontroller_qos_ipdscpmap': {
            'params': ['adom', 'ip-dscp-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map',
                '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}',
                '/pm/config/global/obj/switch-controller/qos/ip-dscp-map',
                '/pm/config/global/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}'
            ]
        },
        'switchcontroller_qos_ipdscpmap_map': {
            'params': ['adom', 'ip-dscp-map', 'map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map',
                '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}',
                '/pm/config/global/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map',
                '/pm/config/global/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}'
            ]
        },
        'switchcontroller_qos_qospolicy': {
            'params': ['adom', 'qos-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/qos-policy',
                '/pm/config/adom/{adom}/obj/switch-controller/qos/qos-policy/{qos-policy}',
                '/pm/config/global/obj/switch-controller/qos/qos-policy',
                '/pm/config/global/obj/switch-controller/qos/qos-policy/{qos-policy}'
            ]
        },
        'switchcontroller_qos_queuepolicy': {
            'params': ['adom', 'queue-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy',
                '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy/{queue-policy}',
                '/pm/config/global/obj/switch-controller/qos/queue-policy',
                '/pm/config/global/obj/switch-controller/qos/queue-policy/{queue-policy}'
            ]
        },
        'switchcontroller_qos_queuepolicy_cosqueue': {
            'params': ['adom', 'cos-queue', 'queue-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy/{queue-policy}/cos-queue',
                '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}',
                '/pm/config/global/obj/switch-controller/qos/queue-policy/{queue-policy}/cos-queue',
                '/pm/config/global/obj/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}'
            ]
        },
        'switchcontroller_securitypolicy_8021x': {
            'params': ['802-1X', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/security-policy/802-1X',
                '/pm/config/adom/{adom}/obj/switch-controller/security-policy/802-1X/{802-1X}',
                '/pm/config/global/obj/switch-controller/security-policy/802-1X',
                '/pm/config/global/obj/switch-controller/security-policy/802-1X/{802-1X}'
            ]
        },
        'switchcontroller_securitypolicy_captiveportal': {
            'params': ['adom', 'captive-portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/security-policy/captive-portal',
                '/pm/config/adom/{adom}/obj/switch-controller/security-policy/captive-portal/{captive-portal}',
                '/pm/config/global/obj/switch-controller/security-policy/captive-portal',
                '/pm/config/global/obj/switch-controller/security-policy/captive-portal/{captive-portal}'
            ],
            'v_range': [['6.0.0', '6.2.1']]
        },
        'switchcontroller_switchinterfacetag': {
            'params': ['adom', 'switch-interface-tag'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/switch-interface-tag',
                '/pm/config/adom/{adom}/obj/switch-controller/switch-interface-tag/{switch-interface-tag}',
                '/pm/config/global/obj/switch-controller/switch-interface-tag',
                '/pm/config/global/obj/switch-controller/switch-interface-tag/{switch-interface-tag}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'switchcontroller_trafficpolicy': {
            'params': ['adom', 'traffic-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/traffic-policy',
                '/pm/config/adom/{adom}/obj/switch-controller/traffic-policy/{traffic-policy}',
                '/pm/config/global/obj/switch-controller/traffic-policy',
                '/pm/config/global/obj/switch-controller/traffic-policy/{traffic-policy}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'switchcontroller_vlanpolicy': {
            'params': ['adom', 'vlan-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/vlan-policy',
                '/pm/config/adom/{adom}/obj/switch-controller/vlan-policy/{vlan-policy}',
                '/pm/config/global/obj/switch-controller/vlan-policy',
                '/pm/config/global/obj/switch-controller/vlan-policy/{vlan-policy}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'sys_ha_status': {
            'params': [],
            'urls': [
                '/sys/ha/status'
            ]
        },
        'sys_status': {
            'params': [],
            'urls': [
                '/sys/status'
            ]
        },
        'system_admin_group': {
            'params': ['group'],
            'urls': [
                '/cli/global/system/admin/group',
                '/cli/global/system/admin/group/{group}'
            ]
        },
        'system_admin_group_member': {
            'params': ['group', 'member'],
            'urls': [
                '/cli/global/system/admin/group/{group}/member',
                '/cli/global/system/admin/group/{group}/member/{member}'
            ]
        },
        'system_admin_ldap': {
            'params': ['ldap'],
            'urls': [
                '/cli/global/system/admin/ldap',
                '/cli/global/system/admin/ldap/{ldap}'
            ]
        },
        'system_admin_ldap_adom': {
            'params': ['adom', 'ldap'],
            'urls': [
                '/cli/global/system/admin/ldap/{ldap}/adom',
                '/cli/global/system/admin/ldap/{ldap}/adom/{adom}'
            ]
        },
        'system_admin_profile': {
            'params': ['profile'],
            'urls': [
                '/cli/global/system/admin/profile',
                '/cli/global/system/admin/profile/{profile}'
            ]
        },
        'system_admin_profile_datamaskcustomfields': {
            'params': ['datamask-custom-fields', 'profile'],
            'urls': [
                '/cli/global/system/admin/profile/{profile}/datamask-custom-fields',
                '/cli/global/system/admin/profile/{profile}/datamask-custom-fields/{datamask-custom-fields}'
            ]
        },
        'system_admin_profile_writepasswdprofiles': {
            'params': ['profile', 'write-passwd-profiles'],
            'urls': [
                '/cli/global/system/admin/profile/{profile}/write-passwd-profiles',
                '/cli/global/system/admin/profile/{profile}/write-passwd-profiles/{write-passwd-profiles}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'system_admin_profile_writepasswduserlist': {
            'params': ['profile', 'write-passwd-user-list'],
            'urls': [
                '/cli/global/system/admin/profile/{profile}/write-passwd-user-list',
                '/cli/global/system/admin/profile/{profile}/write-passwd-user-list/{write-passwd-user-list}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'system_admin_radius': {
            'params': ['radius'],
            'urls': [
                '/cli/global/system/admin/radius',
                '/cli/global/system/admin/radius/{radius}'
            ]
        },
        'system_admin_setting': {
            'params': [],
            'urls': [
                '/cli/global/system/admin/setting'
            ]
        },
        'system_admin_tacacs': {
            'params': ['tacacs'],
            'urls': [
                '/cli/global/system/admin/tacacs',
                '/cli/global/system/admin/tacacs/{tacacs}'
            ]
        },
        'system_admin_user': {
            'params': ['user'],
            'urls': [
                '/cli/global/system/admin/user',
                '/cli/global/system/admin/user/{user}'
            ]
        },
        'system_admin_user_adom': {
            'params': ['adom', 'user'],
            'urls': [
                '/cli/global/system/admin/user/{user}/adom',
                '/cli/global/system/admin/user/{user}/adom/{adom}'
            ]
        },
        'system_admin_user_adomexclude': {
            'params': ['adom-exclude', 'user'],
            'urls': [
                '/cli/global/system/admin/user/{user}/adom-exclude',
                '/cli/global/system/admin/user/{user}/adom-exclude/{adom-exclude}'
            ],
            'v_range': [['6.0.0', '7.0.2']]
        },
        'system_admin_user_appfilter': {
            'params': ['app-filter', 'user'],
            'urls': [
                '/cli/global/system/admin/user/{user}/app-filter',
                '/cli/global/system/admin/user/{user}/app-filter/{app-filter}'
            ]
        },
        'system_admin_user_dashboard': {
            'params': ['dashboard', 'user'],
            'urls': [
                '/cli/global/system/admin/user/{user}/dashboard',
                '/cli/global/system/admin/user/{user}/dashboard/{dashboard}'
            ]
        },
        'system_admin_user_dashboardtabs': {
            'params': ['dashboard-tabs', 'user'],
            'urls': [
                '/cli/global/system/admin/user/{user}/dashboard-tabs',
                '/cli/global/system/admin/user/{user}/dashboard-tabs/{dashboard-tabs}'
            ]
        },
        'system_admin_user_ipsfilter': {
            'params': ['ips-filter', 'user'],
            'urls': [
                '/cli/global/system/admin/user/{user}/ips-filter',
                '/cli/global/system/admin/user/{user}/ips-filter/{ips-filter}'
            ]
        },
        'system_admin_user_metadata': {
            'params': ['meta-data', 'user'],
            'urls': [
                '/cli/global/system/admin/user/{user}/meta-data',
                '/cli/global/system/admin/user/{user}/meta-data/{meta-data}'
            ]
        },
        'system_admin_user_policyblock': {
            'params': ['policy-block', 'user'],
            'urls': [
                '/cli/global/system/admin/user/{user}/policy-block',
                '/cli/global/system/admin/user/{user}/policy-block/{policy-block}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'system_admin_user_policypackage': {
            'params': ['policy-package', 'user'],
            'urls': [
                '/cli/global/system/admin/user/{user}/policy-package',
                '/cli/global/system/admin/user/{user}/policy-package/{policy-package}'
            ]
        },
        'system_admin_user_restrictdevvdom': {
            'params': ['restrict-dev-vdom', 'user'],
            'urls': [
                '/cli/global/system/admin/user/{user}/restrict-dev-vdom',
                '/cli/global/system/admin/user/{user}/restrict-dev-vdom/{restrict-dev-vdom}'
            ],
            'v_range': [['6.0.0', '6.2.3'], ['6.4.0', '6.4.0']]
        },
        'system_admin_user_webfilter': {
            'params': ['user', 'web-filter'],
            'urls': [
                '/cli/global/system/admin/user/{user}/web-filter',
                '/cli/global/system/admin/user/{user}/web-filter/{web-filter}'
            ]
        },
        'system_alertconsole': {
            'params': [],
            'urls': [
                '/cli/global/system/alert-console'
            ]
        },
        'system_alertemail': {
            'params': [],
            'urls': [
                '/cli/global/system/alertemail'
            ]
        },
        'system_alertevent': {
            'params': ['alert-event'],
            'urls': [
                '/cli/global/system/alert-event',
                '/cli/global/system/alert-event/{alert-event}'
            ]
        },
        'system_alertevent_alertdestination': {
            'params': ['alert-destination', 'alert-event'],
            'urls': [
                '/cli/global/system/alert-event/{alert-event}/alert-destination',
                '/cli/global/system/alert-event/{alert-event}/alert-destination/{alert-destination}'
            ]
        },
        'system_autodelete': {
            'params': [],
            'urls': [
                '/cli/global/system/auto-delete'
            ]
        },
        'system_autodelete_dlpfilesautodeletion': {
            'params': [],
            'urls': [
                '/cli/global/system/auto-delete/dlp-files-auto-deletion'
            ]
        },
        'system_autodelete_logautodeletion': {
            'params': [],
            'urls': [
                '/cli/global/system/auto-delete/log-auto-deletion'
            ]
        },
        'system_autodelete_quarantinefilesautodeletion': {
            'params': [],
            'urls': [
                '/cli/global/system/auto-delete/quarantine-files-auto-deletion'
            ]
        },
        'system_autodelete_reportautodeletion': {
            'params': [],
            'urls': [
                '/cli/global/system/auto-delete/report-auto-deletion'
            ]
        },
        'system_backup_allsettings': {
            'params': [],
            'urls': [
                '/cli/global/system/backup/all-settings'
            ]
        },
        'system_certificate_ca': {
            'params': ['ca'],
            'urls': [
                '/cli/global/system/certificate/ca',
                '/cli/global/system/certificate/ca/{ca}'
            ]
        },
        'system_certificate_crl': {
            'params': ['crl'],
            'urls': [
                '/cli/global/system/certificate/crl',
                '/cli/global/system/certificate/crl/{crl}'
            ]
        },
        'system_certificate_local': {
            'params': ['local'],
            'urls': [
                '/cli/global/system/certificate/local',
                '/cli/global/system/certificate/local/{local}'
            ]
        },
        'system_certificate_oftp': {
            'params': [],
            'urls': [
                '/cli/global/system/certificate/oftp'
            ]
        },
        'system_certificate_remote': {
            'params': ['remote'],
            'urls': [
                '/cli/global/system/certificate/remote',
                '/cli/global/system/certificate/remote/{remote}'
            ]
        },
        'system_certificate_ssh': {
            'params': ['ssh'],
            'urls': [
                '/cli/global/system/certificate/ssh',
                '/cli/global/system/certificate/ssh/{ssh}'
            ]
        },
        'system_connector': {
            'params': [],
            'urls': [
                '/cli/global/system/connector'
            ]
        },
        'system_csf': {
            'params': [],
            'urls': [
                '/cli/global/system/csf'
            ],
            'v_range': [['7.4.1', '']]
        },
        'system_csf_fabricconnector': {
            'params': ['fabric-connector'],
            'urls': [
                '/cli/global/system/csf/fabric-connector',
                '/cli/global/system/csf/fabric-connector/{fabric-connector}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'system_csf_trustedlist': {
            'params': ['trusted-list'],
            'urls': [
                '/cli/global/system/csf/trusted-list',
                '/cli/global/system/csf/trusted-list/{trusted-list}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'system_customlanguage': {
            'params': ['adom', 'custom-language'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/custom-language',
                '/pm/config/adom/{adom}/obj/system/custom-language/{custom-language}',
                '/pm/config/global/obj/system/custom-language',
                '/pm/config/global/obj/system/custom-language/{custom-language}'
            ]
        },
        'system_dhcp_server': {
            'params': ['adom', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server',
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}',
                '/pm/config/global/obj/system/dhcp/server',
                '/pm/config/global/obj/system/dhcp/server/{server}'
            ]
        },
        'system_dhcp_server_excluderange': {
            'params': ['adom', 'exclude-range', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/exclude-range',
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/exclude-range/{exclude-range}',
                '/pm/config/global/obj/system/dhcp/server/{server}/exclude-range',
                '/pm/config/global/obj/system/dhcp/server/{server}/exclude-range/{exclude-range}'
            ]
        },
        'system_dhcp_server_iprange': {
            'params': ['adom', 'ip-range', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/ip-range',
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/ip-range/{ip-range}',
                '/pm/config/global/obj/system/dhcp/server/{server}/ip-range',
                '/pm/config/global/obj/system/dhcp/server/{server}/ip-range/{ip-range}'
            ]
        },
        'system_dhcp_server_options': {
            'params': ['adom', 'options', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/options',
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/options/{options}',
                '/pm/config/global/obj/system/dhcp/server/{server}/options',
                '/pm/config/global/obj/system/dhcp/server/{server}/options/{options}'
            ]
        },
        'system_dhcp_server_reservedaddress': {
            'params': ['adom', 'reserved-address', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/reserved-address',
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/reserved-address/{reserved-address}',
                '/pm/config/global/obj/system/dhcp/server/{server}/reserved-address',
                '/pm/config/global/obj/system/dhcp/server/{server}/reserved-address/{reserved-address}'
            ]
        },
        'system_dm': {
            'params': [],
            'urls': [
                '/cli/global/system/dm'
            ]
        },
        'system_dns': {
            'params': [],
            'urls': [
                '/cli/global/system/dns'
            ]
        },
        'system_docker': {
            'params': [],
            'urls': [
                '/cli/global/system/docker'
            ],
            'v_range': [['6.4.0', '7.0.13'], ['7.2.0', '7.2.10'], ['7.4.0', '']]
        },
        'system_externalresource': {
            'params': ['adom', 'external-resource'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/external-resource',
                '/pm/config/adom/{adom}/obj/system/external-resource/{external-resource}',
                '/pm/config/global/obj/system/external-resource',
                '/pm/config/global/obj/system/external-resource/{external-resource}'
            ]
        },
        'system_externalresource_dynamicmapping': {
            'params': ['adom', 'external-resource'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/external-resource/{external-resource}/dynamic_mapping',
                '/pm/config/global/obj/system/external-resource/{external-resource}/dynamic_mapping'
            ],
            'v_range': [['7.6.2', '']]
        },
        'system_fips': {
            'params': [],
            'urls': [
                '/cli/global/system/fips'
            ]
        },
        'system_fmgcluster': {
            'params': [],
            'urls': [
                '/cli/global/system/fmg-cluster'
            ],
            'v_range': [['7.6.0', '']]
        },
        'system_fmgcluster_peer': {
            'params': ['peer'],
            'urls': [
                '/cli/global/system/fmg-cluster/peer',
                '/cli/global/system/fmg-cluster/peer/{peer}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'system_fortiguard': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/fortiguard',
                '/pm/config/global/obj/system/fortiguard'
            ]
        },
        'system_fortiview_autocache': {
            'params': [],
            'urls': [
                '/cli/global/system/fortiview/auto-cache'
            ]
        },
        'system_fortiview_setting': {
            'params': [],
            'urls': [
                '/cli/global/system/fortiview/setting'
            ]
        },
        'system_geoipcountry': {
            'params': ['adom', 'geoip-country'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-country',
                '/pm/config/adom/{adom}/obj/system/geoip-country/{geoip-country}',
                '/pm/config/global/obj/system/geoip-country',
                '/pm/config/global/obj/system/geoip-country/{geoip-country}'
            ]
        },
        'system_geoipoverride': {
            'params': ['adom', 'geoip-override'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-override',
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}',
                '/pm/config/global/obj/system/geoip-override',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}'
            ]
        },
        'system_geoipoverride_ip6range': {
            'params': ['adom', 'geoip-override', 'ip6-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}/ip6-range',
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}/ip6-range/{ip6-range}',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}/ip6-range',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}/ip6-range/{ip6-range}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'system_geoipoverride_iprange': {
            'params': ['adom', 'geoip-override', 'ip-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}/ip-range',
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}/ip-range/{ip-range}',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}/ip-range',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}/ip-range/{ip-range}'
            ]
        },
        'system_global': {
            'params': [],
            'urls': [
                '/cli/global/system/global'
            ]
        },
        'system_guiact': {
            'params': [],
            'urls': [
                '/cli/global/system/guiact'
            ],
            'v_range': [['6.0.0', '7.0.11'], ['7.2.0', '7.2.4'], ['7.4.0', '7.4.0']]
        },
        'system_ha': {
            'params': [],
            'urls': [
                '/cli/global/system/ha'
            ]
        },
        'system_ha_monitoredinterfaces': {
            'params': ['monitored-interfaces'],
            'urls': [
                '/cli/global/system/ha/monitored-interfaces',
                '/cli/global/system/ha/monitored-interfaces/{monitored-interfaces}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'system_ha_monitoredips': {
            'params': ['monitored-ips'],
            'urls': [
                '/cli/global/system/ha/monitored-ips',
                '/cli/global/system/ha/monitored-ips/{monitored-ips}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'system_ha_peer': {
            'params': ['peer'],
            'urls': [
                '/cli/global/system/ha/peer',
                '/cli/global/system/ha/peer/{peer}'
            ]
        },
        'system_hascheduledcheck': {
            'params': [],
            'urls': [
                '/cli/global/system/ha-scheduled-check'
            ],
            'v_range': [['7.0.1', '']]
        },
        'system_interface': {
            'params': ['interface'],
            'urls': [
                '/cli/global/system/interface',
                '/cli/global/system/interface/{interface}'
            ]
        },
        'system_interface_ipv6': {
            'params': ['interface'],
            'urls': [
                '/cli/global/system/interface/{interface}/ipv6'
            ]
        },
        'system_interface_member': {
            'params': ['interface', 'member'],
            'urls': [
                '/cli/global/system/interface/{interface}/member',
                '/cli/global/system/interface/{interface}/member/{member}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'system_localinpolicy': {
            'params': ['local-in-policy'],
            'urls': [
                '/cli/global/system/local-in-policy',
                '/cli/global/system/local-in-policy/{local-in-policy}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'system_localinpolicy6': {
            'params': ['local-in-policy6'],
            'urls': [
                '/cli/global/system/local-in-policy6',
                '/cli/global/system/local-in-policy6/{local-in-policy6}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'system_locallog_disk_filter': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/disk/filter'
            ]
        },
        'system_locallog_disk_setting': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/disk/setting'
            ]
        },
        'system_locallog_fortianalyzer2_filter': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer2/filter'
            ]
        },
        'system_locallog_fortianalyzer2_setting': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer2/setting'
            ]
        },
        'system_locallog_fortianalyzer3_filter': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer3/filter'
            ]
        },
        'system_locallog_fortianalyzer3_setting': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer3/setting'
            ]
        },
        'system_locallog_fortianalyzer_filter': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer/filter'
            ]
        },
        'system_locallog_fortianalyzer_setting': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/fortianalyzer/setting'
            ]
        },
        'system_locallog_memory_filter': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/memory/filter'
            ]
        },
        'system_locallog_memory_setting': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/memory/setting'
            ]
        },
        'system_locallog_setting': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/setting'
            ]
        },
        'system_locallog_syslogd2_filter': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/syslogd2/filter'
            ]
        },
        'system_locallog_syslogd2_setting': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/syslogd2/setting'
            ]
        },
        'system_locallog_syslogd3_filter': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/syslogd3/filter'
            ]
        },
        'system_locallog_syslogd3_setting': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/syslogd3/setting'
            ]
        },
        'system_locallog_syslogd_filter': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/syslogd/filter'
            ]
        },
        'system_locallog_syslogd_setting': {
            'params': [],
            'urls': [
                '/cli/global/system/locallog/syslogd/setting'
            ]
        },
        'system_log_alert': {
            'params': [],
            'urls': [
                '/cli/global/system/log/alert'
            ]
        },
        'system_log_devicedisable': {
            'params': ['device-disable'],
            'urls': [
                '/cli/global/system/log/device-disable',
                '/cli/global/system/log/device-disable/{device-disable}'
            ],
            'v_range': [['6.4.4', '7.4.6'], ['7.6.0', '7.6.2']]
        },
        'system_log_deviceselector': {
            'params': ['device-selector'],
            'urls': [
                '/cli/global/system/log/device-selector',
                '/cli/global/system/log/device-selector/{device-selector}'
            ],
            'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']]
        },
        'system_log_fospolicystats': {
            'params': [],
            'urls': [
                '/cli/global/system/log/fos-policy-stats'
            ],
            'v_range': [['7.0.2', '']]
        },
        'system_log_interfacestats': {
            'params': [],
            'urls': [
                '/cli/global/system/log/interface-stats'
            ],
            'v_range': [['6.2.1', '']]
        },
        'system_log_ioc': {
            'params': [],
            'urls': [
                '/cli/global/system/log/ioc'
            ]
        },
        'system_log_maildomain': {
            'params': ['mail-domain'],
            'urls': [
                '/cli/global/system/log/mail-domain',
                '/cli/global/system/log/mail-domain/{mail-domain}'
            ]
        },
        'system_log_ratelimit': {
            'params': [],
            'urls': [
                '/cli/global/system/log/ratelimit'
            ],
            'v_range': [['6.4.8', '']]
        },
        'system_log_ratelimit_device': {
            'params': ['device'],
            'urls': [
                '/cli/global/system/log/ratelimit/device',
                '/cli/global/system/log/ratelimit/device/{device}'
            ],
            'v_range': [['6.4.8', '7.0.2']]
        },
        'system_log_ratelimit_ratelimits': {
            'params': ['ratelimits'],
            'urls': [
                '/cli/global/system/log/ratelimit/ratelimits',
                '/cli/global/system/log/ratelimit/ratelimits/{ratelimits}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'system_log_settings': {
            'params': [],
            'urls': [
                '/cli/global/system/log/settings'
            ]
        },
        'system_log_settings_rollinganalyzer': {
            'params': [],
            'urls': [
                '/cli/global/system/log/settings/rolling-analyzer'
            ]
        },
        'system_log_settings_rollinglocal': {
            'params': [],
            'urls': [
                '/cli/global/system/log/settings/rolling-local'
            ]
        },
        'system_log_settings_rollingregular': {
            'params': [],
            'urls': [
                '/cli/global/system/log/settings/rolling-regular'
            ]
        },
        'system_log_topology': {
            'params': [],
            'urls': [
                '/cli/global/system/log/topology'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']]
        },
        'system_log_ueba': {
            'params': [],
            'urls': [
                '/cli/global/system/log/ueba'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_logfetch_clientprofile': {
            'params': ['client-profile'],
            'urls': [
                '/cli/global/system/log-fetch/client-profile',
                '/cli/global/system/log-fetch/client-profile/{client-profile}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'system_logfetch_clientprofile_devicefilter': {
            'params': ['client-profile', 'device-filter'],
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}/device-filter',
                '/cli/global/system/log-fetch/client-profile/{client-profile}/device-filter/{device-filter}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'system_logfetch_clientprofile_logfilter': {
            'params': ['client-profile', 'log-filter'],
            'urls': [
                '/cli/global/system/log-fetch/client-profile/{client-profile}/log-filter',
                '/cli/global/system/log-fetch/client-profile/{client-profile}/log-filter/{log-filter}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'system_logfetch_serversettings': {
            'params': [],
            'urls': [
                '/cli/global/system/log-fetch/server-settings'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'system_mail': {
            'params': ['mail'],
            'urls': [
                '/cli/global/system/mail',
                '/cli/global/system/mail/{mail}'
            ]
        },
        'system_mcpolicydisabledadoms': {
            'params': ['mc-policy-disabled-adoms'],
            'urls': [
                '/cli/global/system/global/mc-policy-disabled-adoms',
                '/cli/global/system/global/mc-policy-disabled-adoms/{mc-policy-disabled-adoms}'
            ],
            'v_range': [['6.2.3', '']]
        },
        'system_meta': {
            'params': ['adom', 'meta'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/meta',
                '/pm/config/adom/{adom}/obj/system/meta/{meta}',
                '/pm/config/global/obj/system/meta',
                '/pm/config/global/obj/system/meta/{meta}'
            ]
        },
        'system_meta_sysmetafields': {
            'params': ['adom', 'meta', 'sys_meta_fields'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/meta/{meta}/sys_meta_fields',
                '/pm/config/adom/{adom}/obj/system/meta/{meta}/sys_meta_fields/{sys_meta_fields}',
                '/pm/config/global/obj/system/meta/{meta}/sys_meta_fields',
                '/pm/config/global/obj/system/meta/{meta}/sys_meta_fields/{sys_meta_fields}'
            ]
        },
        'system_metadata_admins': {
            'params': ['admins'],
            'urls': [
                '/cli/global/system/metadata/admins',
                '/cli/global/system/metadata/admins/{admins}'
            ]
        },
        'system_npu': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu',
                '/pm/config/global/obj/system/npu'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_backgroundssescan': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/background-sse-scan',
                '/pm/config/global/obj/system/npu/background-sse-scan'
            ],
            'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']]
        },
        'system_npu_dosoptions': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/dos-options',
                '/pm/config/global/obj/system/npu/dos-options'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_dswdtsprofile': {
            'params': ['adom', 'dsw-dts-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/dsw-dts-profile',
                '/pm/config/adom/{adom}/obj/system/npu/dsw-dts-profile/{dsw-dts-profile}',
                '/pm/config/global/obj/system/npu/dsw-dts-profile',
                '/pm/config/global/obj/system/npu/dsw-dts-profile/{dsw-dts-profile}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_dswqueuedtsprofile': {
            'params': ['adom', 'dsw-queue-dts-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/dsw-queue-dts-profile',
                '/pm/config/adom/{adom}/obj/system/npu/dsw-queue-dts-profile/{dsw-queue-dts-profile}',
                '/pm/config/global/obj/system/npu/dsw-queue-dts-profile',
                '/pm/config/global/obj/system/npu/dsw-queue-dts-profile/{dsw-queue-dts-profile}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_fpanomaly': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/fp-anomaly',
                '/pm/config/global/obj/system/npu/fp-anomaly'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_hpe': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/hpe',
                '/pm/config/global/obj/system/npu/hpe'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_icmpratectrl': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/icmp-rate-ctrl',
                '/pm/config/global/obj/system/npu/icmp-rate-ctrl'
            ],
            'v_range': [['7.4.3', '']]
        },
        'system_npu_ipreassembly': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/ip-reassembly',
                '/pm/config/global/obj/system/npu/ip-reassembly'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_isfnpqueues': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/isf-np-queues',
                '/pm/config/global/obj/system/npu/isf-np-queues'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_npqueues': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/np-queues',
                '/pm/config/global/obj/system/npu/np-queues'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_npqueues_ethernettype': {
            'params': ['adom', 'ethernet-type'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/ethernet-type',
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/ethernet-type/{ethernet-type}',
                '/pm/config/global/obj/system/npu/np-queues/ethernet-type',
                '/pm/config/global/obj/system/npu/np-queues/ethernet-type/{ethernet-type}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_npqueues_ipprotocol': {
            'params': ['adom', 'ip-protocol'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/ip-protocol',
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/ip-protocol/{ip-protocol}',
                '/pm/config/global/obj/system/npu/np-queues/ip-protocol',
                '/pm/config/global/obj/system/npu/np-queues/ip-protocol/{ip-protocol}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_npqueues_ipservice': {
            'params': ['adom', 'ip-service'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/ip-service',
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/ip-service/{ip-service}',
                '/pm/config/global/obj/system/npu/np-queues/ip-service',
                '/pm/config/global/obj/system/npu/np-queues/ip-service/{ip-service}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_npqueues_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/profile',
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/profile/{profile}',
                '/pm/config/global/obj/system/npu/np-queues/profile',
                '/pm/config/global/obj/system/npu/np-queues/profile/{profile}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_npqueues_scheduler': {
            'params': ['adom', 'scheduler'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/scheduler',
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/scheduler/{scheduler}',
                '/pm/config/global/obj/system/npu/np-queues/scheduler',
                '/pm/config/global/obj/system/npu/np-queues/scheduler/{scheduler}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_nputcam': {
            'params': ['adom', 'npu-tcam'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/npu-tcam',
                '/pm/config/adom/{adom}/obj/system/npu/npu-tcam/{npu-tcam}',
                '/pm/config/global/obj/system/npu/npu-tcam',
                '/pm/config/global/obj/system/npu/npu-tcam/{npu-tcam}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'system_npu_nputcam_data': {
            'params': ['adom', 'npu-tcam'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/npu-tcam/{npu-tcam}/data',
                '/pm/config/global/obj/system/npu/npu-tcam/{npu-tcam}/data'
            ],
            'v_range': [['7.4.2', '']]
        },
        'system_npu_nputcam_mask': {
            'params': ['adom', 'npu-tcam'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/npu-tcam/{npu-tcam}/mask',
                '/pm/config/global/obj/system/npu/npu-tcam/{npu-tcam}/mask'
            ],
            'v_range': [['7.4.2', '']]
        },
        'system_npu_nputcam_miract': {
            'params': ['adom', 'npu-tcam'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/npu-tcam/{npu-tcam}/mir-act',
                '/pm/config/global/obj/system/npu/npu-tcam/{npu-tcam}/mir-act'
            ],
            'v_range': [['7.4.2', '']]
        },
        'system_npu_nputcam_priact': {
            'params': ['adom', 'npu-tcam'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/npu-tcam/{npu-tcam}/pri-act',
                '/pm/config/global/obj/system/npu/npu-tcam/{npu-tcam}/pri-act'
            ],
            'v_range': [['7.4.2', '']]
        },
        'system_npu_nputcam_sact': {
            'params': ['adom', 'npu-tcam'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/npu-tcam/{npu-tcam}/sact',
                '/pm/config/global/obj/system/npu/npu-tcam/{npu-tcam}/sact'
            ],
            'v_range': [['7.4.2', '']]
        },
        'system_npu_nputcam_tact': {
            'params': ['adom', 'npu-tcam'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/npu-tcam/{npu-tcam}/tact',
                '/pm/config/global/obj/system/npu/npu-tcam/{npu-tcam}/tact'
            ],
            'v_range': [['7.4.2', '']]
        },
        'system_npu_portcpumap': {
            'params': ['adom', 'port-cpu-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/port-cpu-map',
                '/pm/config/adom/{adom}/obj/system/npu/port-cpu-map/{port-cpu-map}',
                '/pm/config/global/obj/system/npu/port-cpu-map',
                '/pm/config/global/obj/system/npu/port-cpu-map/{port-cpu-map}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_portnpumap': {
            'params': ['adom', 'port-npu-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/port-npu-map',
                '/pm/config/adom/{adom}/obj/system/npu/port-npu-map/{port-npu-map}',
                '/pm/config/global/obj/system/npu/port-npu-map',
                '/pm/config/global/obj/system/npu/port-npu-map/{port-npu-map}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_portpathoption': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/port-path-option',
                '/pm/config/global/obj/system/npu/port-path-option'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_priorityprotocol': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/priority-protocol',
                '/pm/config/global/obj/system/npu/priority-protocol'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_ssehascan': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/sse-ha-scan',
                '/pm/config/global/obj/system/npu/sse-ha-scan'
            ],
            'v_range': [['6.4.10', '6.4.15'], ['7.0.4', '7.0.14'], ['7.2.1', '']]
        },
        'system_npu_swehhash': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/sw-eh-hash',
                '/pm/config/global/obj/system/npu/sw-eh-hash'
            ],
            'v_range': [['7.0.1', '']]
        },
        'system_npu_swtrhash': {
            'params': ['adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/sw-tr-hash',
                '/pm/config/global/obj/system/npu/sw-tr-hash'
            ],
            'v_range': [['7.2.4', '']]
        },
        'system_npu_tcptimeoutprofile': {
            'params': ['adom', 'tcp-timeout-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/tcp-timeout-profile',
                '/pm/config/adom/{adom}/obj/system/npu/tcp-timeout-profile/{tcp-timeout-profile}',
                '/pm/config/global/obj/system/npu/tcp-timeout-profile',
                '/pm/config/global/obj/system/npu/tcp-timeout-profile/{tcp-timeout-profile}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_udptimeoutprofile': {
            'params': ['adom', 'udp-timeout-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/udp-timeout-profile',
                '/pm/config/adom/{adom}/obj/system/npu/udp-timeout-profile/{udp-timeout-profile}',
                '/pm/config/global/obj/system/npu/udp-timeout-profile',
                '/pm/config/global/obj/system/npu/udp-timeout-profile/{udp-timeout-profile}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_ntp': {
            'params': [],
            'urls': [
                '/cli/global/system/ntp'
            ]
        },
        'system_ntp_ntpserver': {
            'params': ['ntpserver'],
            'urls': [
                '/cli/global/system/ntp/ntpserver',
                '/cli/global/system/ntp/ntpserver/{ntpserver}'
            ]
        },
        'system_objecttag': {
            'params': ['adom', 'object-tag'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/object-tag',
                '/pm/config/adom/{adom}/obj/system/object-tag/{object-tag}',
                '/pm/config/global/obj/system/object-tag',
                '/pm/config/global/obj/system/object-tag/{object-tag}'
            ],
            'v_range': [['6.2.0', '6.4.15']]
        },
        'system_objecttagging': {
            'params': ['adom', 'object-tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/object-tagging',
                '/pm/config/adom/{adom}/obj/system/object-tagging/{object-tagging}',
                '/pm/config/global/obj/system/object-tagging',
                '/pm/config/global/obj/system/object-tagging/{object-tagging}'
            ]
        },
        'system_passwordpolicy': {
            'params': [],
            'urls': [
                '/cli/global/system/password-policy'
            ]
        },
        'system_performance': {
            'params': [],
            'urls': [
                '/cli/global/system/performance'
            ]
        },
        'system_replacemsggroup': {
            'params': ['adom', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}',
                '/pm/config/global/obj/system/replacemsg-group',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}'
            ]
        },
        'system_replacemsggroup_admin': {
            'params': ['admin', 'adom', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/admin',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/admin/{admin}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/admin',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/admin/{admin}'
            ]
        },
        'system_replacemsggroup_alertmail': {
            'params': ['adom', 'alertmail', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/alertmail',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/alertmail/{alertmail}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/alertmail',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/alertmail/{alertmail}'
            ]
        },
        'system_replacemsggroup_auth': {
            'params': ['adom', 'auth', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/auth',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/auth/{auth}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/auth',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/auth/{auth}'
            ]
        },
        'system_replacemsggroup_automation': {
            'params': ['adom', 'automation', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/automation',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/automation/{automation}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/automation',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/automation/{automation}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'system_replacemsggroup_custommessage': {
            'params': ['adom', 'custom-message', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/custom-message',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/custom-message/{custom-message}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/custom-message',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/custom-message/{custom-message}'
            ]
        },
        'system_replacemsggroup_devicedetectionportal': {
            'params': ['adom', 'device-detection-portal', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/device-detection-portal',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/device-detection-portal/{device-detection-portal}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/device-detection-portal',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/device-detection-portal/{device-detection-portal}'
            ]
        },
        'system_replacemsggroup_ec': {
            'params': ['adom', 'ec', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/ec',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/ec/{ec}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/ec',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/ec/{ec}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'system_replacemsggroup_fortiguardwf': {
            'params': ['adom', 'fortiguard-wf', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/fortiguard-wf',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/fortiguard-wf/{fortiguard-wf}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/fortiguard-wf',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/fortiguard-wf/{fortiguard-wf}'
            ]
        },
        'system_replacemsggroup_ftp': {
            'params': ['adom', 'ftp', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/ftp',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/ftp/{ftp}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/ftp',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/ftp/{ftp}'
            ]
        },
        'system_replacemsggroup_http': {
            'params': ['adom', 'http', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/http',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/http/{http}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/http',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/http/{http}'
            ]
        },
        'system_replacemsggroup_icap': {
            'params': ['adom', 'icap', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/icap',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/icap/{icap}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/icap',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/icap/{icap}'
            ]
        },
        'system_replacemsggroup_mail': {
            'params': ['adom', 'mail', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mail',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mail/{mail}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mail',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mail/{mail}'
            ]
        },
        'system_replacemsggroup_mm1': {
            'params': ['adom', 'mm1', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm1',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm1/{mm1}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm1',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm1/{mm1}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'system_replacemsggroup_mm3': {
            'params': ['adom', 'mm3', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm3',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm3/{mm3}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm3',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm3/{mm3}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'system_replacemsggroup_mm4': {
            'params': ['adom', 'mm4', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm4',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm4/{mm4}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm4',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm4/{mm4}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'system_replacemsggroup_mm7': {
            'params': ['adom', 'mm7', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm7',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm7/{mm7}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm7',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm7/{mm7}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'system_replacemsggroup_mms': {
            'params': ['adom', 'mms', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mms',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mms/{mms}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mms',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mms/{mms}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'system_replacemsggroup_nacquar': {
            'params': ['adom', 'nac-quar', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/nac-quar',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/nac-quar/{nac-quar}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/nac-quar',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/nac-quar/{nac-quar}'
            ]
        },
        'system_replacemsggroup_nntp': {
            'params': ['adom', 'nntp', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/nntp',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/nntp/{nntp}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/nntp',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/nntp/{nntp}'
            ]
        },
        'system_replacemsggroup_spam': {
            'params': ['adom', 'replacemsg-group', 'spam'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/spam',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/spam/{spam}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/spam',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/spam/{spam}'
            ]
        },
        'system_replacemsggroup_sslvpn': {
            'params': ['adom', 'replacemsg-group', 'sslvpn'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/sslvpn',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/sslvpn/{sslvpn}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/sslvpn',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/sslvpn/{sslvpn}'
            ]
        },
        'system_replacemsggroup_trafficquota': {
            'params': ['adom', 'replacemsg-group', 'traffic-quota'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/traffic-quota',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/traffic-quota/{traffic-quota}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/traffic-quota',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/traffic-quota/{traffic-quota}'
            ]
        },
        'system_replacemsggroup_utm': {
            'params': ['adom', 'replacemsg-group', 'utm'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/utm',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/utm/{utm}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/utm',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/utm/{utm}'
            ]
        },
        'system_replacemsggroup_webproxy': {
            'params': ['adom', 'replacemsg-group', 'webproxy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/webproxy',
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/webproxy/{webproxy}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/webproxy',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/webproxy/{webproxy}'
            ]
        },
        'system_replacemsgimage': {
            'params': ['adom', 'replacemsg-image'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-image',
                '/pm/config/adom/{adom}/obj/system/replacemsg-image/{replacemsg-image}',
                '/pm/config/global/obj/system/replacemsg-image',
                '/pm/config/global/obj/system/replacemsg-image/{replacemsg-image}'
            ]
        },
        'system_report_autocache': {
            'params': [],
            'urls': [
                '/cli/global/system/report/auto-cache'
            ]
        },
        'system_report_estbrowsetime': {
            'params': [],
            'urls': [
                '/cli/global/system/report/est-browse-time'
            ]
        },
        'system_report_group': {
            'params': ['group'],
            'urls': [
                '/cli/global/system/report/group',
                '/cli/global/system/report/group/{group}'
            ]
        },
        'system_report_group_chartalternative': {
            'params': ['chart-alternative', 'group'],
            'urls': [
                '/cli/global/system/report/group/{group}/chart-alternative',
                '/cli/global/system/report/group/{group}/chart-alternative/{chart-alternative}'
            ]
        },
        'system_report_group_groupby': {
            'params': ['group', 'group-by'],
            'urls': [
                '/cli/global/system/report/group/{group}/group-by',
                '/cli/global/system/report/group/{group}/group-by/{group-by}'
            ]
        },
        'system_report_setting': {
            'params': [],
            'urls': [
                '/cli/global/system/report/setting'
            ]
        },
        'system_route': {
            'params': ['route'],
            'urls': [
                '/cli/global/system/route',
                '/cli/global/system/route/{route}'
            ]
        },
        'system_route6': {
            'params': ['route6'],
            'urls': [
                '/cli/global/system/route6',
                '/cli/global/system/route6/{route6}'
            ]
        },
        'system_saml': {
            'params': [],
            'urls': [
                '/cli/global/system/saml'
            ]
        },
        'system_saml_fabricidp': {
            'params': ['fabric-idp'],
            'urls': [
                '/cli/global/system/saml/fabric-idp',
                '/cli/global/system/saml/fabric-idp/{fabric-idp}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'system_saml_serviceproviders': {
            'params': ['service-providers'],
            'urls': [
                '/cli/global/system/saml/service-providers',
                '/cli/global/system/saml/service-providers/{service-providers}'
            ]
        },
        'system_sdnconnector': {
            'params': ['adom', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}',
                '/pm/config/global/obj/system/sdn-connector',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}'
            ]
        },
        'system_sdnconnector_compartmentlist': {
            'params': ['adom', 'compartment-list', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/compartment-list',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/compartment-list/{compartment-list}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/compartment-list',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/compartment-list/{compartment-list}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'system_sdnconnector_externalaccountlist': {
            'params': ['adom', 'external-account-list', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-account-list',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-account-list/{external-account-list}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-account-list',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-account-list/{external-account-list}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'system_sdnconnector_externalip': {
            'params': ['adom', 'external-ip', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-ip',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-ip/{external-ip}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-ip',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-ip/{external-ip}'
            ]
        },
        'system_sdnconnector_forwardingrule': {
            'params': ['adom', 'forwarding-rule', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/forwarding-rule',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/forwarding-rule/{forwarding-rule}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/forwarding-rule',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/forwarding-rule/{forwarding-rule}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'system_sdnconnector_gcpprojectlist': {
            'params': ['adom', 'gcp-project-list', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/gcp-project-list',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/gcp-project-list/{gcp-project-list}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/gcp-project-list',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/gcp-project-list/{gcp-project-list}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']]
        },
        'system_sdnconnector_nic': {
            'params': ['adom', 'nic', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic/{nic}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic/{nic}'
            ]
        },
        'system_sdnconnector_nic_ip': {
            'params': ['adom', 'ip', 'nic', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip/{ip}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip/{ip}'
            ]
        },
        'system_sdnconnector_ociregionlist': {
            'params': ['adom', 'oci-region-list', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/oci-region-list',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/oci-region-list/{oci-region-list}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/oci-region-list',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/oci-region-list/{oci-region-list}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'system_sdnconnector_route': {
            'params': ['adom', 'route', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route/{route}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route/{route}'
            ]
        },
        'system_sdnconnector_routetable': {
            'params': ['adom', 'route-table', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route-table',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route-table',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}'
            ]
        },
        'system_sdnconnector_routetable_route': {
            'params': ['adom', 'route', 'route-table', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}/route',
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}/route/{route}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}/route',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}/route/{route}'
            ]
        },
        'system_sdnproxy': {
            'params': ['adom', 'sdn-proxy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-proxy',
                '/pm/config/adom/{adom}/obj/system/sdn-proxy/{sdn-proxy}',
                '/pm/config/global/obj/system/sdn-proxy',
                '/pm/config/global/obj/system/sdn-proxy/{sdn-proxy}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'system_smsserver': {
            'params': ['adom', 'sms-server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sms-server',
                '/pm/config/adom/{adom}/obj/system/sms-server/{sms-server}',
                '/pm/config/global/obj/system/sms-server',
                '/pm/config/global/obj/system/sms-server/{sms-server}'
            ]
        },
        'system_sniffer': {
            'params': ['sniffer'],
            'urls': [
                '/cli/global/system/sniffer',
                '/cli/global/system/sniffer/{sniffer}'
            ],
            'v_range': [['6.2.2', '']]
        },
        'system_snmp_community': {
            'params': ['community'],
            'urls': [
                '/cli/global/system/snmp/community',
                '/cli/global/system/snmp/community/{community}'
            ]
        },
        'system_snmp_community_hosts': {
            'params': ['community', 'hosts'],
            'urls': [
                '/cli/global/system/snmp/community/{community}/hosts',
                '/cli/global/system/snmp/community/{community}/hosts/{hosts}'
            ]
        },
        'system_snmp_community_hosts6': {
            'params': ['community', 'hosts6'],
            'urls': [
                '/cli/global/system/snmp/community/{community}/hosts6',
                '/cli/global/system/snmp/community/{community}/hosts6/{hosts6}'
            ]
        },
        'system_snmp_sysinfo': {
            'params': [],
            'urls': [
                '/cli/global/system/snmp/sysinfo'
            ]
        },
        'system_snmp_user': {
            'params': ['user'],
            'urls': [
                '/cli/global/system/snmp/user',
                '/cli/global/system/snmp/user/{user}'
            ]
        },
        'system_socfabric': {
            'params': [],
            'urls': [
                '/cli/global/system/soc-fabric'
            ],
            'v_range': [['7.0.0', '']]
        },
        'system_socfabric_trustedlist': {
            'params': ['trusted-list'],
            'urls': [
                '/cli/global/system/soc-fabric/trusted-list',
                '/cli/global/system/soc-fabric/trusted-list/{trusted-list}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'system_sql': {
            'params': [],
            'urls': [
                '/cli/global/system/sql'
            ]
        },
        'system_sql_customindex': {
            'params': ['custom-index'],
            'urls': [
                '/cli/global/system/sql/custom-index',
                '/cli/global/system/sql/custom-index/{custom-index}'
            ]
        },
        'system_sql_customskipidx': {
            'params': ['custom-skipidx'],
            'urls': [
                '/cli/global/system/sql/custom-skipidx',
                '/cli/global/system/sql/custom-skipidx/{custom-skipidx}'
            ],
            'v_range': [['6.2.3', '']]
        },
        'system_sql_tsindexfield': {
            'params': ['ts-index-field'],
            'urls': [
                '/cli/global/system/sql/ts-index-field',
                '/cli/global/system/sql/ts-index-field/{ts-index-field}'
            ]
        },
        'system_sslciphersuites': {
            'params': ['ssl-cipher-suites'],
            'urls': [
                '/cli/global/system/global/ssl-cipher-suites',
                '/cli/global/system/global/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'v_range': [['6.4.8', '6.4.15'], ['7.0.2', '']]
        },
        'system_status': {
            'params': [],
            'urls': [
                '/cli/global/system/status'
            ]
        },
        'system_syslog': {
            'params': ['syslog'],
            'urls': [
                '/cli/global/system/syslog',
                '/cli/global/system/syslog/{syslog}'
            ]
        },
        'system_virtualwirepair': {
            'params': ['adom', 'virtual-wire-pair'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/virtual-wire-pair',
                '/pm/config/adom/{adom}/obj/system/virtual-wire-pair/{virtual-wire-pair}',
                '/pm/config/global/obj/system/virtual-wire-pair',
                '/pm/config/global/obj/system/virtual-wire-pair/{virtual-wire-pair}'
            ]
        },
        'system_webproxy': {
            'params': [],
            'urls': [
                '/cli/global/system/web-proxy'
            ],
            'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']]
        },
        'system_workflow_approvalmatrix': {
            'params': ['approval-matrix'],
            'urls': [
                '/cli/global/system/workflow/approval-matrix',
                '/cli/global/system/workflow/approval-matrix/{approval-matrix}'
            ]
        },
        'system_workflow_approvalmatrix_approver': {
            'params': ['approval-matrix', 'approver'],
            'urls': [
                '/cli/global/system/workflow/approval-matrix/{approval-matrix}/approver',
                '/cli/global/system/workflow/approval-matrix/{approval-matrix}/approver/{approver}'
            ]
        },
        'task_task': {
            'params': ['task'],
            'urls': [
                '/task/task',
                '/task/task/{task}'
            ]
        },
        'task_task_history': {
            'params': ['history', 'task'],
            'urls': [
                '/task/task/{task}/history',
                '/task/task/{task}/history/{history}'
            ],
            'v_range': [['6.0.0', '6.2.13']]
        },
        'task_task_line': {
            'params': ['line', 'task'],
            'urls': [
                '/task/task/{task}/line',
                '/task/task/{task}/line/{line}'
            ]
        },
        'task_task_line_history': {
            'params': ['history', 'line', 'task'],
            'urls': [
                '/task/task/{task}/line/{line}/history',
                '/task/task/{task}/line/{line}/history/{history}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'telemetrycontroller_agentprofile': {
            'params': ['adom', 'agent-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/telemetry-controller/agent-profile',
                '/pm/config/adom/{adom}/obj/telemetry-controller/agent-profile/{agent-profile}',
                '/pm/config/global/obj/telemetry-controller/agent-profile',
                '/pm/config/global/obj/telemetry-controller/agent-profile/{agent-profile}'
            ],
            'v_range': [['7.6.3', '']]
        },
        'telemetrycontroller_application_predefine': {
            'params': ['adom', 'predefine'],
            'urls': [
                '/pm/config/adom/{adom}/obj/telemetry-controller/application/predefine',
                '/pm/config/adom/{adom}/obj/telemetry-controller/application/predefine/{predefine}',
                '/pm/config/global/obj/telemetry-controller/application/predefine',
                '/pm/config/global/obj/telemetry-controller/application/predefine/{predefine}'
            ],
            'v_range': [['7.6.3', '']]
        },
        'telemetrycontroller_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/telemetry-controller/profile',
                '/pm/config/adom/{adom}/obj/telemetry-controller/profile/{profile}',
                '/pm/config/global/obj/telemetry-controller/profile',
                '/pm/config/global/obj/telemetry-controller/profile/{profile}'
            ],
            'v_range': [['7.6.3', '']]
        },
        'telemetrycontroller_profile_application': {
            'params': ['adom', 'application', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/telemetry-controller/profile/{profile}/application',
                '/pm/config/adom/{adom}/obj/telemetry-controller/profile/{profile}/application/{application}',
                '/pm/config/global/obj/telemetry-controller/profile/{profile}/application',
                '/pm/config/global/obj/telemetry-controller/profile/{profile}/application/{application}'
            ],
            'v_range': [['7.6.3', '']]
        },
        'telemetrycontroller_profile_application_sla': {
            'params': ['adom', 'application', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/telemetry-controller/profile/{profile}/application/{application}/sla',
                '/pm/config/global/obj/telemetry-controller/profile/{profile}/application/{application}/sla'
            ],
            'v_range': [['7.6.3', '']]
        },
        'template': {
            'params': ['adom', 'template'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cli/template',
                '/pm/config/adom/{adom}/obj/cli/template/{template}',
                '/pm/config/global/obj/cli/template',
                '/pm/config/global/obj/cli/template/{template}'
            ]
        },
        'templategroup': {
            'params': ['adom', 'template-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cli/template-group',
                '/pm/config/adom/{adom}/obj/cli/template-group/{template-group}',
                '/pm/config/global/obj/cli/template-group',
                '/pm/config/global/obj/cli/template-group/{template-group}'
            ]
        },
        'ums_setting': {
            'params': ['adom', 'setting'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ums/setting',
                '/pm/config/adom/{adom}/obj/ums/setting/{setting}',
                '/pm/config/global/obj/ums/setting',
                '/pm/config/global/obj/ums/setting/{setting}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'user_adgrp': {
            'params': ['adgrp', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/adgrp',
                '/pm/config/adom/{adom}/obj/user/adgrp/{adgrp}',
                '/pm/config/global/obj/user/adgrp',
                '/pm/config/global/obj/user/adgrp/{adgrp}'
            ]
        },
        'user_certificate': {
            'params': ['adom', 'certificate'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/certificate',
                '/pm/config/adom/{adom}/obj/user/certificate/{certificate}',
                '/pm/config/global/obj/user/certificate',
                '/pm/config/global/obj/user/certificate/{certificate}'
            ],
            'v_range': [['7.0.8', '7.0.14'], ['7.2.3', '']]
        },
        'user_clearpass': {
            'params': ['adom', 'clearpass'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/clearpass',
                '/pm/config/adom/{adom}/obj/user/clearpass/{clearpass}',
                '/pm/config/global/obj/user/clearpass',
                '/pm/config/global/obj/user/clearpass/{clearpass}'
            ],
            'v_range': [['6.2.1', '']]
        },
        'user_connector': {
            'params': ['adom', 'connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/connector',
                '/pm/config/adom/{adom}/obj/user/connector/{connector}',
                '/pm/config/global/obj/user/connector',
                '/pm/config/global/obj/user/connector/{connector}'
            ],
            'v_range': [['7.0.1', '']]
        },
        'user_device': {
            'params': ['adom', 'device'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device',
                '/pm/config/adom/{adom}/obj/user/device/{device}',
                '/pm/config/global/obj/user/device',
                '/pm/config/global/obj/user/device/{device}'
            ],
            'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']]
        },
        'user_device_dynamicmapping': {
            'params': ['adom', 'device', 'dynamic_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/user/device/{device}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/device/{device}/dynamic_mapping',
                '/pm/config/global/obj/user/device/{device}/dynamic_mapping/{dynamic_mapping}'
            ],
            'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']]
        },
        'user_device_tagging': {
            'params': ['adom', 'device', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}/tagging',
                '/pm/config/adom/{adom}/obj/user/device/{device}/tagging/{tagging}',
                '/pm/config/global/obj/user/device/{device}/tagging',
                '/pm/config/global/obj/user/device/{device}/tagging/{tagging}'
            ],
            'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']]
        },
        'user_deviceaccesslist': {
            'params': ['adom', 'device-access-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-access-list',
                '/pm/config/adom/{adom}/obj/user/device-access-list/{device-access-list}',
                '/pm/config/global/obj/user/device-access-list',
                '/pm/config/global/obj/user/device-access-list/{device-access-list}'
            ],
            'v_range': [['6.2.2', '7.2.1']]
        },
        'user_deviceaccesslist_devicelist': {
            'params': ['adom', 'device-access-list', 'device-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-access-list/{device-access-list}/device-list',
                '/pm/config/adom/{adom}/obj/user/device-access-list/{device-access-list}/device-list/{device-list}',
                '/pm/config/global/obj/user/device-access-list/{device-access-list}/device-list',
                '/pm/config/global/obj/user/device-access-list/{device-access-list}/device-list/{device-list}'
            ],
            'v_range': [['6.2.2', '7.2.1']]
        },
        'user_devicecategory': {
            'params': ['adom', 'device-category'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-category',
                '/pm/config/adom/{adom}/obj/user/device-category/{device-category}',
                '/pm/config/global/obj/user/device-category',
                '/pm/config/global/obj/user/device-category/{device-category}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'user_devicegroup': {
            'params': ['adom', 'device-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group',
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}',
                '/pm/config/global/obj/user/device-group',
                '/pm/config/global/obj/user/device-group/{device-group}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'user_devicegroup_dynamicmapping': {
            'params': ['adom', 'device-group', 'dynamic_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/device-group/{device-group}/dynamic_mapping',
                '/pm/config/global/obj/user/device-group/{device-group}/dynamic_mapping/{dynamic_mapping}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'user_devicegroup_tagging': {
            'params': ['adom', 'device-group', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/tagging',
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/tagging/{tagging}',
                '/pm/config/global/obj/user/device-group/{device-group}/tagging',
                '/pm/config/global/obj/user/device-group/{device-group}/tagging/{tagging}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'user_domaincontroller': {
            'params': ['adom', 'domain-controller'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/domain-controller',
                '/pm/config/adom/{adom}/obj/user/domain-controller/{domain-controller}',
                '/pm/config/global/obj/user/domain-controller',
                '/pm/config/global/obj/user/domain-controller/{domain-controller}'
            ],
            'v_range': [['6.2.1', '']]
        },
        'user_domaincontroller_extraserver': {
            'params': ['adom', 'domain-controller', 'extra-server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/domain-controller/{domain-controller}/extra-server',
                '/pm/config/adom/{adom}/obj/user/domain-controller/{domain-controller}/extra-server/{extra-server}',
                '/pm/config/global/obj/user/domain-controller/{domain-controller}/extra-server',
                '/pm/config/global/obj/user/domain-controller/{domain-controller}/extra-server/{extra-server}'
            ],
            'v_range': [['6.2.1', '']]
        },
        'user_exchange': {
            'params': ['adom', 'exchange'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/exchange',
                '/pm/config/adom/{adom}/obj/user/exchange/{exchange}',
                '/pm/config/global/obj/user/exchange',
                '/pm/config/global/obj/user/exchange/{exchange}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'user_externalidentityprovider': {
            'params': ['adom', 'external-identity-provider'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/external-identity-provider',
                '/pm/config/adom/{adom}/obj/user/external-identity-provider/{external-identity-provider}',
                '/pm/config/global/obj/user/external-identity-provider',
                '/pm/config/global/obj/user/external-identity-provider/{external-identity-provider}'
            ],
            'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'user_flexvm': {
            'params': ['adom', 'flexvm'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/flexvm',
                '/pm/config/adom/{adom}/obj/user/flexvm/{flexvm}',
                '/pm/config/global/obj/user/flexvm',
                '/pm/config/global/obj/user/flexvm/{flexvm}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'user_fortitoken': {
            'params': ['adom', 'fortitoken'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fortitoken',
                '/pm/config/adom/{adom}/obj/user/fortitoken/{fortitoken}',
                '/pm/config/global/obj/user/fortitoken',
                '/pm/config/global/obj/user/fortitoken/{fortitoken}'
            ]
        },
        'user_fsso': {
            'params': ['adom', 'fsso'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso',
                '/pm/config/adom/{adom}/obj/user/fsso/{fsso}',
                '/pm/config/global/obj/user/fsso',
                '/pm/config/global/obj/user/fsso/{fsso}'
            ]
        },
        'user_fsso_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'fsso'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso/{fsso}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/user/fsso/{fsso}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/fsso/{fsso}/dynamic_mapping',
                '/pm/config/global/obj/user/fsso/{fsso}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'user_fssopolling': {
            'params': ['adom', 'fsso-polling'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso-polling',
                '/pm/config/adom/{adom}/obj/user/fsso-polling/{fsso-polling}',
                '/pm/config/global/obj/user/fsso-polling',
                '/pm/config/global/obj/user/fsso-polling/{fsso-polling}'
            ]
        },
        'user_fssopolling_adgrp': {
            'params': ['adgrp', 'adom', 'fsso-polling'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso-polling/{fsso-polling}/adgrp',
                '/pm/config/adom/{adom}/obj/user/fsso-polling/{fsso-polling}/adgrp/{adgrp}',
                '/pm/config/global/obj/user/fsso-polling/{fsso-polling}/adgrp',
                '/pm/config/global/obj/user/fsso-polling/{fsso-polling}/adgrp/{adgrp}'
            ]
        },
        'user_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group',
                '/pm/config/adom/{adom}/obj/user/group/{group}',
                '/pm/config/global/obj/user/group',
                '/pm/config/global/obj/user/group/{group}'
            ]
        },
        'user_group_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping',
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'user_group_dynamicmapping_guest': {
            'params': ['adom', 'dynamic_mapping', 'group', 'guest'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/guest',
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/guest/{guest}',
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/guest',
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/guest/{guest}'
            ],
            'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_group_dynamicmapping_match': {
            'params': ['adom', 'dynamic_mapping', 'group', 'match'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/match',
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/match/{match}',
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/match',
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/match/{match}'
            ],
            'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_group_dynamicmapping_sslvpnoschecklist': {
            'params': ['adom', 'dynamic_mapping', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/sslvpn-os-check-list',
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/sslvpn-os-check-list'
            ],
            'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_group_guest': {
            'params': ['adom', 'group', 'guest'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/guest',
                '/pm/config/adom/{adom}/obj/user/group/{group}/guest/{guest}',
                '/pm/config/global/obj/user/group/{group}/guest',
                '/pm/config/global/obj/user/group/{group}/guest/{guest}'
            ]
        },
        'user_group_match': {
            'params': ['adom', 'group', 'match'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/match',
                '/pm/config/adom/{adom}/obj/user/group/{group}/match/{match}',
                '/pm/config/global/obj/user/group/{group}/match',
                '/pm/config/global/obj/user/group/{group}/match/{match}'
            ]
        },
        'user_json': {
            'params': ['adom', 'json'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/json',
                '/pm/config/adom/{adom}/obj/user/json/{json}',
                '/pm/config/global/obj/user/json',
                '/pm/config/global/obj/user/json/{json}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'user_krbkeytab': {
            'params': ['adom', 'krb-keytab'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/krb-keytab',
                '/pm/config/adom/{adom}/obj/user/krb-keytab/{krb-keytab}',
                '/pm/config/global/obj/user/krb-keytab',
                '/pm/config/global/obj/user/krb-keytab/{krb-keytab}'
            ],
            'v_range': [['6.2.1', '']]
        },
        'user_ldap': {
            'params': ['adom', 'ldap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/ldap',
                '/pm/config/adom/{adom}/obj/user/ldap/{ldap}',
                '/pm/config/global/obj/user/ldap',
                '/pm/config/global/obj/user/ldap/{ldap}'
            ]
        },
        'user_ldap_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'ldap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/ldap/{ldap}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/user/ldap/{ldap}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/ldap/{ldap}/dynamic_mapping',
                '/pm/config/global/obj/user/ldap/{ldap}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'user_local': {
            'params': ['adom', 'local'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/local',
                '/pm/config/adom/{adom}/obj/user/local/{local}',
                '/pm/config/global/obj/user/local',
                '/pm/config/global/obj/user/local/{local}'
            ]
        },
        'user_nsx': {
            'params': ['adom', 'nsx'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/nsx',
                '/pm/config/adom/{adom}/obj/user/nsx/{nsx}',
                '/pm/config/global/obj/user/nsx',
                '/pm/config/global/obj/user/nsx/{nsx}'
            ],
            'v_range': [['6.2.1', '']]
        },
        'user_nsx_service': {
            'params': ['adom', 'nsx', 'service'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/nsx/{nsx}/service',
                '/pm/config/adom/{adom}/obj/user/nsx/{nsx}/service/{service}',
                '/pm/config/global/obj/user/nsx/{nsx}/service',
                '/pm/config/global/obj/user/nsx/{nsx}/service/{service}'
            ],
            'v_range': [['7.0.4', '']]
        },
        'user_passwordpolicy': {
            'params': ['adom', 'password-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/password-policy',
                '/pm/config/adom/{adom}/obj/user/password-policy/{password-policy}',
                '/pm/config/global/obj/user/password-policy',
                '/pm/config/global/obj/user/password-policy/{password-policy}'
            ]
        },
        'user_peer': {
            'params': ['adom', 'peer'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/peer',
                '/pm/config/adom/{adom}/obj/user/peer/{peer}',
                '/pm/config/global/obj/user/peer',
                '/pm/config/global/obj/user/peer/{peer}'
            ]
        },
        'user_peergrp': {
            'params': ['adom', 'peergrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/peergrp',
                '/pm/config/adom/{adom}/obj/user/peergrp/{peergrp}',
                '/pm/config/global/obj/user/peergrp',
                '/pm/config/global/obj/user/peergrp/{peergrp}'
            ]
        },
        'user_pop3': {
            'params': ['adom', 'pop3'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/pop3',
                '/pm/config/adom/{adom}/obj/user/pop3/{pop3}',
                '/pm/config/global/obj/user/pop3',
                '/pm/config/global/obj/user/pop3/{pop3}'
            ]
        },
        'user_pxgrid': {
            'params': ['adom', 'pxgrid'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/pxgrid',
                '/pm/config/adom/{adom}/obj/user/pxgrid/{pxgrid}',
                '/pm/config/global/obj/user/pxgrid',
                '/pm/config/global/obj/user/pxgrid/{pxgrid}'
            ]
        },
        'user_radius': {
            'params': ['adom', 'radius'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius',
                '/pm/config/adom/{adom}/obj/user/radius/{radius}',
                '/pm/config/global/obj/user/radius',
                '/pm/config/global/obj/user/radius/{radius}'
            ]
        },
        'user_radius_accountingserver': {
            'params': ['accounting-server', 'adom', 'radius'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/accounting-server',
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/accounting-server/{accounting-server}',
                '/pm/config/global/obj/user/radius/{radius}/accounting-server',
                '/pm/config/global/obj/user/radius/{radius}/accounting-server/{accounting-server}'
            ]
        },
        'user_radius_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'radius'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping',
                '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'user_radius_dynamicmapping_accountingserver': {
            'params': ['accounting-server', 'adom', 'dynamic_mapping', 'radius'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}/accounting-server',
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}/accounting-server/{accounting-server}',
                '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}/accounting-server',
                '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}/accounting-server/{accounting-server}'
            ],
            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_saml': {
            'params': ['adom', 'saml'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/saml',
                '/pm/config/adom/{adom}/obj/user/saml/{saml}',
                '/pm/config/global/obj/user/saml',
                '/pm/config/global/obj/user/saml/{saml}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'user_saml_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'saml'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/saml/{saml}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/user/saml/{saml}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/saml/{saml}/dynamic_mapping',
                '/pm/config/global/obj/user/saml/{saml}/dynamic_mapping/{dynamic_mapping}'
            ],
            'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']]
        },
        'user_scim': {
            'params': ['adom', 'scim'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/scim',
                '/pm/config/adom/{adom}/obj/user/scim/{scim}',
                '/pm/config/global/obj/user/scim',
                '/pm/config/global/obj/user/scim/{scim}'
            ],
            'v_range': [['7.6.3', '']]
        },
        'user_securityexemptlist': {
            'params': ['adom', 'security-exempt-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/security-exempt-list',
                '/pm/config/adom/{adom}/obj/user/security-exempt-list/{security-exempt-list}',
                '/pm/config/global/obj/user/security-exempt-list',
                '/pm/config/global/obj/user/security-exempt-list/{security-exempt-list}'
            ]
        },
        'user_securityexemptlist_rule': {
            'params': ['adom', 'rule', 'security-exempt-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/security-exempt-list/{security-exempt-list}/rule',
                '/pm/config/adom/{adom}/obj/user/security-exempt-list/{security-exempt-list}/rule/{rule}',
                '/pm/config/global/obj/user/security-exempt-list/{security-exempt-list}/rule',
                '/pm/config/global/obj/user/security-exempt-list/{security-exempt-list}/rule/{rule}'
            ]
        },
        'user_tacacs': {
            'params': ['adom', 'tacacs+'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/tacacs+',
                '/pm/config/adom/{adom}/obj/user/tacacs+/{tacacs+}',
                '/pm/config/global/obj/user/tacacs+',
                '/pm/config/global/obj/user/tacacs+/{tacacs+}'
            ]
        },
        'user_tacacs_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'tacacs+'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/tacacs+/{tacacs+}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/user/tacacs+/{tacacs+}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/tacacs+/{tacacs+}/dynamic_mapping',
                '/pm/config/global/obj/user/tacacs+/{tacacs+}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'user_vcenter': {
            'params': ['adom', 'vcenter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/vcenter',
                '/pm/config/adom/{adom}/obj/user/vcenter/{vcenter}',
                '/pm/config/global/obj/user/vcenter',
                '/pm/config/global/obj/user/vcenter/{vcenter}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'user_vcenter_rule': {
            'params': ['adom', 'rule', 'vcenter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/vcenter/{vcenter}/rule',
                '/pm/config/adom/{adom}/obj/user/vcenter/{vcenter}/rule/{rule}',
                '/pm/config/global/obj/user/vcenter/{vcenter}/rule',
                '/pm/config/global/obj/user/vcenter/{vcenter}/rule/{rule}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'utmprofile': {
            'params': ['adom', 'utm-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/utm-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/utm-profile/{utm-profile}',
                '/pm/config/global/obj/wireless-controller/utm-profile',
                '/pm/config/global/obj/wireless-controller/utm-profile/{utm-profile}'
            ],
            'v_range': [['6.2.2', '']]
        },
        'vap': {
            'params': ['adom', 'vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap',
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}',
                '/pm/config/global/obj/wireless-controller/vap',
                '/pm/config/global/obj/wireless-controller/vap/{vap}'
            ]
        },
        'vap_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/dynamic_mapping',
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/dynamic_mapping',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/dynamic_mapping/{dynamic_mapping}'
            ]
        },
        'vap_macfilterlist': {
            'params': ['adom', 'mac-filter-list', 'vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/mac-filter-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/mac-filter-list',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}'
            ]
        },
        'vap_mpskkey': {
            'params': ['adom', 'mpsk-key', 'vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/mpsk-key',
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/mpsk-key/{mpsk-key}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/mpsk-key',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/mpsk-key/{mpsk-key}'
            ]
        },
        'vap_portalmessageoverrides': {
            'params': ['adom', 'vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/portal-message-overrides',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/portal-message-overrides'
            ]
        },
        'vap_vlanname': {
            'params': ['adom', 'vap', 'vlan-name'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/vlan-name',
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/vlan-name/{vlan-name}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/vlan-name',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/vlan-name/{vlan-name}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'vap_vlanpool': {
            'params': ['adom', 'vap', 'vlan-pool'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/vlan-pool',
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/vlan-pool',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}'
            ]
        },
        'vapgroup': {
            'params': ['adom', 'vap-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap-group',
                '/pm/config/adom/{adom}/obj/wireless-controller/vap-group/{vap-group}',
                '/pm/config/global/obj/wireless-controller/vap-group',
                '/pm/config/global/obj/wireless-controller/vap-group/{vap-group}'
            ]
        },
        'videofilter_keyword': {
            'params': ['adom', 'keyword'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/keyword',
                '/pm/config/adom/{adom}/obj/videofilter/keyword/{keyword}',
                '/pm/config/global/obj/videofilter/keyword',
                '/pm/config/global/obj/videofilter/keyword/{keyword}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'videofilter_keyword_word': {
            'params': ['adom', 'keyword', 'word'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/keyword/{keyword}/word',
                '/pm/config/adom/{adom}/obj/videofilter/keyword/{keyword}/word/{word}',
                '/pm/config/global/obj/videofilter/keyword/{keyword}/word',
                '/pm/config/global/obj/videofilter/keyword/{keyword}/word/{word}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'videofilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/profile',
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}',
                '/pm/config/global/obj/videofilter/profile',
                '/pm/config/global/obj/videofilter/profile/{profile}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'videofilter_profile_filters': {
            'params': ['adom', 'filters', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/filters',
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/filters/{filters}',
                '/pm/config/global/obj/videofilter/profile/{profile}/filters',
                '/pm/config/global/obj/videofilter/profile/{profile}/filters/{filters}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'videofilter_profile_fortiguardcategory': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/fortiguard-category',
                '/pm/config/global/obj/videofilter/profile/{profile}/fortiguard-category'
            ],
            'v_range': [['7.0.0', '']]
        },
        'videofilter_profile_fortiguardcategory_filters': {
            'params': ['adom', 'filters', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/fortiguard-category/filters',
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/fortiguard-category/filters/{filters}',
                '/pm/config/global/obj/videofilter/profile/{profile}/fortiguard-category/filters',
                '/pm/config/global/obj/videofilter/profile/{profile}/fortiguard-category/filters/{filters}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'videofilter_youtubechannelfilter': {
            'params': ['adom', 'youtube-channel-filter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter',
                '/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}',
                '/pm/config/global/obj/videofilter/youtube-channel-filter',
                '/pm/config/global/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'videofilter_youtubechannelfilter_entries': {
            'params': ['adom', 'entries', 'youtube-channel-filter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}/entries',
                '/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}/entries/{entries}',
                '/pm/config/global/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}/entries',
                '/pm/config/global/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}/entries/{entries}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'videofilter_youtubekey': {
            'params': ['adom', 'youtube-key'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/youtube-key',
                '/pm/config/adom/{adom}/obj/videofilter/youtube-key/{youtube-key}',
                '/pm/config/global/obj/videofilter/youtube-key',
                '/pm/config/global/obj/videofilter/youtube-key/{youtube-key}'
            ],
            'v_range': [['7.4.2', '7.4.3'], ['7.6.0', '7.6.1']]
        },
        'virtualpatch_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/virtual-patch/profile',
                '/pm/config/adom/{adom}/obj/virtual-patch/profile/{profile}',
                '/pm/config/global/obj/virtual-patch/profile',
                '/pm/config/global/obj/virtual-patch/profile/{profile}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'virtualpatch_profile_exemption': {
            'params': ['adom', 'exemption', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/virtual-patch/profile/{profile}/exemption',
                '/pm/config/adom/{adom}/obj/virtual-patch/profile/{profile}/exemption/{exemption}',
                '/pm/config/global/obj/virtual-patch/profile/{profile}/exemption',
                '/pm/config/global/obj/virtual-patch/profile/{profile}/exemption/{exemption}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'voip_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/voip/profile',
                '/pm/config/adom/{adom}/obj/voip/profile/{profile}',
                '/pm/config/global/obj/voip/profile',
                '/pm/config/global/obj/voip/profile/{profile}'
            ]
        },
        'voip_profile_msrp': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/voip/profile/{profile}/msrp',
                '/pm/config/global/obj/voip/profile/{profile}/msrp'
            ],
            'v_range': [['7.0.2', '']]
        },
        'voip_profile_sccp': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/voip/profile/{profile}/sccp',
                '/pm/config/global/obj/voip/profile/{profile}/sccp'
            ]
        },
        'voip_profile_sip': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/voip/profile/{profile}/sip',
                '/pm/config/global/obj/voip/profile/{profile}/sip'
            ]
        },
        'vpn_certificate_ca': {
            'params': ['adom', 'ca'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/ca',
                '/pm/config/adom/{adom}/obj/vpn/certificate/ca/{ca}',
                '/pm/config/global/obj/vpn/certificate/ca',
                '/pm/config/global/obj/vpn/certificate/ca/{ca}'
            ]
        },
        'vpn_certificate_ocspserver': {
            'params': ['adom', 'ocsp-server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/ocsp-server',
                '/pm/config/adom/{adom}/obj/vpn/certificate/ocsp-server/{ocsp-server}',
                '/pm/config/global/obj/vpn/certificate/ocsp-server',
                '/pm/config/global/obj/vpn/certificate/ocsp-server/{ocsp-server}'
            ]
        },
        'vpn_certificate_remote': {
            'params': ['adom', 'remote'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/remote',
                '/pm/config/adom/{adom}/obj/vpn/certificate/remote/{remote}',
                '/pm/config/global/obj/vpn/certificate/remote',
                '/pm/config/global/obj/vpn/certificate/remote/{remote}'
            ]
        },
        'vpn_ipsec_fec': {
            'params': ['adom', 'fec'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ipsec/fec',
                '/pm/config/adom/{adom}/obj/vpn/ipsec/fec/{fec}',
                '/pm/config/global/obj/vpn/ipsec/fec',
                '/pm/config/global/obj/vpn/ipsec/fec/{fec}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'vpn_ipsec_fec_mappings': {
            'params': ['adom', 'fec', 'mappings'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ipsec/fec/{fec}/mappings',
                '/pm/config/adom/{adom}/obj/vpn/ipsec/fec/{fec}/mappings/{mappings}',
                '/pm/config/global/obj/vpn/ipsec/fec/{fec}/mappings',
                '/pm/config/global/obj/vpn/ipsec/fec/{fec}/mappings/{mappings}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'vpn_ssl_settings': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings'
            ],
            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']]
        },
        'vpn_ssl_settings_authenticationrule': {
            'params': ['authentication-rule', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/authentication-rule',
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/authentication-rule/{authentication-rule}'
            ],
            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']]
        },
        'vpnmgr_node': {
            'params': ['adom', 'node'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node',
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}',
                '/pm/config/global/obj/vpnmgr/node',
                '/pm/config/global/obj/vpnmgr/node/{node}'
            ]
        },
        'vpnmgr_node_iprange': {
            'params': ['adom', 'ip-range', 'node'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/ip-range',
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/ip-range/{ip-range}',
                '/pm/config/global/obj/vpnmgr/node/{node}/ip-range',
                '/pm/config/global/obj/vpnmgr/node/{node}/ip-range/{ip-range}'
            ]
        },
        'vpnmgr_node_ipv4excluderange': {
            'params': ['adom', 'ipv4-exclude-range', 'node'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/ipv4-exclude-range',
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/ipv4-exclude-range/{ipv4-exclude-range}',
                '/pm/config/global/obj/vpnmgr/node/{node}/ipv4-exclude-range',
                '/pm/config/global/obj/vpnmgr/node/{node}/ipv4-exclude-range/{ipv4-exclude-range}'
            ]
        },
        'vpnmgr_node_protectedsubnet': {
            'params': ['adom', 'node', 'protected_subnet'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/protected_subnet',
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/protected_subnet/{protected_subnet}',
                '/pm/config/global/obj/vpnmgr/node/{node}/protected_subnet',
                '/pm/config/global/obj/vpnmgr/node/{node}/protected_subnet/{protected_subnet}'
            ]
        },
        'vpnmgr_node_summaryaddr': {
            'params': ['adom', 'node', 'summary_addr'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/summary_addr',
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/summary_addr/{summary_addr}',
                '/pm/config/global/obj/vpnmgr/node/{node}/summary_addr',
                '/pm/config/global/obj/vpnmgr/node/{node}/summary_addr/{summary_addr}'
            ]
        },
        'vpnmgr_vpntable': {
            'params': ['adom', 'vpntable'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/vpntable',
                '/pm/config/adom/{adom}/obj/vpnmgr/vpntable/{vpntable}',
                '/pm/config/global/obj/vpnmgr/vpntable',
                '/pm/config/global/obj/vpnmgr/vpntable/{vpntable}'
            ]
        },
        'vpnsslweb_hostchecksoftware': {
            'params': ['adom', 'host-check-software'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}',
                '/pm/config/global/obj/vpn/ssl/web/host-check-software',
                '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}'
            ]
        },
        'vpnsslweb_hostchecksoftware_checkitemlist': {
            'params': ['adom', 'check-item-list', 'host-check-software'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list/{check-item-list}',
                '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list',
                '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list/{check-item-list}'
            ]
        },
        'vpnsslweb_portal': {
            'params': ['adom', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}',
                '/pm/config/global/obj/vpn/ssl/web/portal',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}'
            ]
        },
        'vpnsslweb_portal_bookmarkgroup': {
            'params': ['adom', 'bookmark-group', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}'
            ]
        },
        'vpnsslweb_portal_bookmarkgroup_bookmarks': {
            'params': ['adom', 'bookmark-group', 'bookmarks', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}'
            ]
        },
        'vpnsslweb_portal_bookmarkgroup_bookmarks_formdata': {
            'params': ['adom', 'bookmark-group', 'bookmarks', 'form-data', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data/{form-data}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data/{form-data}'
            ]
        },
        'vpnsslweb_portal_landingpage': {
            'params': ['adom', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/landing-page',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/landing-page'
            ],
            'v_range': [['7.4.0', '']]
        },
        'vpnsslweb_portal_landingpage_formdata': {
            'params': ['adom', 'form-data', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/landing-page/form-data',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/landing-page/form-data/{form-data}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/landing-page/form-data',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/landing-page/form-data/{form-data}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'vpnsslweb_portal_macaddrcheckrule': {
            'params': ['adom', 'mac-addr-check-rule', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule/{mac-addr-check-rule}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule/{mac-addr-check-rule}'
            ]
        },
        'vpnsslweb_portal_oschecklist': {
            'params': ['adom', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/os-check-list',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/os-check-list'
            ]
        },
        'vpnsslweb_portal_splitdns': {
            'params': ['adom', 'portal', 'split-dns'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/split-dns',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/split-dns/{split-dns}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/split-dns',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/split-dns/{split-dns}'
            ]
        },
        'vpnsslweb_realm': {
            'params': ['adom', 'realm'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/realm',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/realm/{realm}',
                '/pm/config/global/obj/vpn/ssl/web/realm',
                '/pm/config/global/obj/vpn/ssl/web/realm/{realm}'
            ]
        },
        'vpnsslweb_virtualdesktopapplist': {
            'params': ['adom', 'virtual-desktop-app-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/virtual-desktop-app-list',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}',
                '/pm/config/global/obj/vpn/ssl/web/virtual-desktop-app-list',
                '/pm/config/global/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'vpnsslweb_virtualdesktopapplist_apps': {
            'params': ['adom', 'apps', 'virtual-desktop-app-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}/apps',
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}/apps/{apps}',
                '/pm/config/global/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}/apps',
                '/pm/config/global/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}/apps/{apps}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'waf_mainclass': {
            'params': ['adom', 'main-class'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/main-class',
                '/pm/config/adom/{adom}/obj/waf/main-class/{main-class}',
                '/pm/config/global/obj/waf/main-class',
                '/pm/config/global/obj/waf/main-class/{main-class}'
            ]
        },
        'waf_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile',
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}',
                '/pm/config/global/obj/waf/profile',
                '/pm/config/global/obj/waf/profile/{profile}'
            ]
        },
        'waf_profile_addresslist': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/address-list',
                '/pm/config/global/obj/waf/profile/{profile}/address-list'
            ]
        },
        'waf_profile_constraint': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint',
                '/pm/config/global/obj/waf/profile/{profile}/constraint'
            ]
        },
        'waf_profile_constraint_contentlength': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/content-length',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/content-length'
            ]
        },
        'waf_profile_constraint_exception': {
            'params': ['adom', 'exception', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/exception',
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/exception/{exception}',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/exception',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/exception/{exception}'
            ]
        },
        'waf_profile_constraint_headerlength': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/header-length',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/header-length'
            ]
        },
        'waf_profile_constraint_hostname': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/hostname',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/hostname'
            ]
        },
        'waf_profile_constraint_linelength': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/line-length',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/line-length'
            ]
        },
        'waf_profile_constraint_malformed': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/malformed',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/malformed'
            ]
        },
        'waf_profile_constraint_maxcookie': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/max-cookie',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/max-cookie'
            ]
        },
        'waf_profile_constraint_maxheaderline': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/max-header-line',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/max-header-line'
            ]
        },
        'waf_profile_constraint_maxrangesegment': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/max-range-segment',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/max-range-segment'
            ]
        },
        'waf_profile_constraint_maxurlparam': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/max-url-param',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/max-url-param'
            ]
        },
        'waf_profile_constraint_method': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/method',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/method'
            ]
        },
        'waf_profile_constraint_paramlength': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/param-length',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/param-length'
            ]
        },
        'waf_profile_constraint_urlparamlength': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/url-param-length',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/url-param-length'
            ]
        },
        'waf_profile_constraint_version': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/version',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/version'
            ]
        },
        'waf_profile_method': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/method',
                '/pm/config/global/obj/waf/profile/{profile}/method'
            ]
        },
        'waf_profile_method_methodpolicy': {
            'params': ['adom', 'method-policy', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/method/method-policy',
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/method/method-policy/{method-policy}',
                '/pm/config/global/obj/waf/profile/{profile}/method/method-policy',
                '/pm/config/global/obj/waf/profile/{profile}/method/method-policy/{method-policy}'
            ]
        },
        'waf_profile_signature': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/signature',
                '/pm/config/global/obj/waf/profile/{profile}/signature'
            ]
        },
        'waf_profile_signature_customsignature': {
            'params': ['adom', 'custom-signature', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/signature/custom-signature',
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/signature/custom-signature/{custom-signature}',
                '/pm/config/global/obj/waf/profile/{profile}/signature/custom-signature',
                '/pm/config/global/obj/waf/profile/{profile}/signature/custom-signature/{custom-signature}'
            ]
        },
        'waf_profile_signature_mainclass': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/signature/main-class',
                '/pm/config/global/obj/waf/profile/{profile}/signature/main-class'
            ]
        },
        'waf_profile_urlaccess': {
            'params': ['adom', 'profile', 'url-access'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access',
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}',
                '/pm/config/global/obj/waf/profile/{profile}/url-access',
                '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}'
            ]
        },
        'waf_profile_urlaccess_accesspattern': {
            'params': ['access-pattern', 'adom', 'profile', 'url-access'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}/access-pattern',
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}/access-pattern/{access-pattern}',
                '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}/access-pattern',
                '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}/access-pattern/{access-pattern}'
            ]
        },
        'waf_signature': {
            'params': ['adom', 'signature'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/signature',
                '/pm/config/adom/{adom}/obj/waf/signature/{signature}',
                '/pm/config/global/obj/waf/signature',
                '/pm/config/global/obj/waf/signature/{signature}'
            ]
        },
        'waf_subclass': {
            'params': ['adom', 'sub-class'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/sub-class',
                '/pm/config/adom/{adom}/obj/waf/sub-class/{sub-class}',
                '/pm/config/global/obj/waf/sub-class',
                '/pm/config/global/obj/waf/sub-class/{sub-class}'
            ]
        },
        'wagprofile': {
            'params': ['adom', 'wag-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wag-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/wag-profile/{wag-profile}',
                '/pm/config/global/obj/wireless-controller/wag-profile',
                '/pm/config/global/obj/wireless-controller/wag-profile/{wag-profile}'
            ],
            'v_range': [['6.2.3', '']]
        },
        'wanopt_authgroup': {
            'params': ['adom', 'auth-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/auth-group',
                '/pm/config/adom/{adom}/obj/wanopt/auth-group/{auth-group}',
                '/pm/config/global/obj/wanopt/auth-group',
                '/pm/config/global/obj/wanopt/auth-group/{auth-group}'
            ]
        },
        'wanopt_peer': {
            'params': ['adom', 'peer'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/peer',
                '/pm/config/adom/{adom}/obj/wanopt/peer/{peer}',
                '/pm/config/global/obj/wanopt/peer',
                '/pm/config/global/obj/wanopt/peer/{peer}'
            ]
        },
        'wanopt_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile',
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}',
                '/pm/config/global/obj/wanopt/profile',
                '/pm/config/global/obj/wanopt/profile/{profile}'
            ]
        },
        'wanopt_profile_cifs': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/cifs',
                '/pm/config/global/obj/wanopt/profile/{profile}/cifs'
            ]
        },
        'wanopt_profile_ftp': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/ftp',
                '/pm/config/global/obj/wanopt/profile/{profile}/ftp'
            ]
        },
        'wanopt_profile_http': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/http',
                '/pm/config/global/obj/wanopt/profile/{profile}/http'
            ]
        },
        'wanopt_profile_mapi': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/mapi',
                '/pm/config/global/obj/wanopt/profile/{profile}/mapi'
            ]
        },
        'wanopt_profile_tcp': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/tcp',
                '/pm/config/global/obj/wanopt/profile/{profile}/tcp'
            ]
        },
        'wanprof_system_sdwan': {
            'params': ['adom', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan'
            ],
            'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_duplication': {
            'params': ['adom', 'duplication', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/duplication',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/duplication/{duplication}'
            ],
            'v_range': [['6.4.2', '']]
        },
        'wanprof_system_sdwan_healthcheck': {
            'params': ['adom', 'health-check', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check/{health-check}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_healthcheck_sla': {
            'params': ['adom', 'health-check', 'sla', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check/{health-check}/sla',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check/{health-check}/sla/{sla}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_members': {
            'params': ['adom', 'members', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/members',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/members/{members}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_neighbor': {
            'params': ['adom', 'neighbor', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/neighbor',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/neighbor/{neighbor}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_service': {
            'params': ['adom', 'service', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/service',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/service/{service}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_service_sla': {
            'params': ['adom', 'service', 'sla', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/service/{service}/sla',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/service/{service}/sla/{sla}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_zone': {
            'params': ['adom', 'wanprof', 'zone'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/zone',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/zone/{zone}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'wanprof_system_virtualwanlink': {
            'params': ['adom', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_healthcheck': {
            'params': ['adom', 'health-check', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check/{health-check}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_healthcheck_sla': {
            'params': ['adom', 'health-check', 'sla', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check/{health-check}/sla',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check/{health-check}/sla/{sla}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_members': {
            'params': ['adom', 'members', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/members',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/members/{members}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_neighbor': {
            'params': ['adom', 'neighbor', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/neighbor',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/neighbor/{neighbor}'
            ],
            'v_range': [['6.2.1', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_service': {
            'params': ['adom', 'service', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/service',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/service/{service}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_service_sla': {
            'params': ['adom', 'service', 'sla', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/service/{service}/sla',
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/service/{service}/sla/{sla}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'webfilter_categories': {
            'params': ['adom', 'categories'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/categories',
                '/pm/config/adom/{adom}/obj/webfilter/categories/{categories}',
                '/pm/config/global/obj/webfilter/categories',
                '/pm/config/global/obj/webfilter/categories/{categories}'
            ]
        },
        'webfilter_content': {
            'params': ['adom', 'content'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content',
                '/pm/config/adom/{adom}/obj/webfilter/content/{content}',
                '/pm/config/global/obj/webfilter/content',
                '/pm/config/global/obj/webfilter/content/{content}'
            ]
        },
        'webfilter_content_entries': {
            'params': ['adom', 'content', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content/{content}/entries',
                '/pm/config/adom/{adom}/obj/webfilter/content/{content}/entries/{entries}',
                '/pm/config/global/obj/webfilter/content/{content}/entries',
                '/pm/config/global/obj/webfilter/content/{content}/entries/{entries}'
            ]
        },
        'webfilter_contentheader': {
            'params': ['adom', 'content-header'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content-header',
                '/pm/config/adom/{adom}/obj/webfilter/content-header/{content-header}',
                '/pm/config/global/obj/webfilter/content-header',
                '/pm/config/global/obj/webfilter/content-header/{content-header}'
            ]
        },
        'webfilter_contentheader_entries': {
            'params': ['adom', 'content-header', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content-header/{content-header}/entries',
                '/pm/config/adom/{adom}/obj/webfilter/content-header/{content-header}/entries/{entries}',
                '/pm/config/global/obj/webfilter/content-header/{content-header}/entries',
                '/pm/config/global/obj/webfilter/content-header/{content-header}/entries/{entries}'
            ]
        },
        'webfilter_ftgdlocalcat': {
            'params': ['adom', 'ftgd-local-cat'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/ftgd-local-cat',
                '/pm/config/adom/{adom}/obj/webfilter/ftgd-local-cat/{ftgd-local-cat}',
                '/pm/config/global/obj/webfilter/ftgd-local-cat',
                '/pm/config/global/obj/webfilter/ftgd-local-cat/{ftgd-local-cat}'
            ]
        },
        'webfilter_ftgdlocalrating': {
            'params': ['adom', 'ftgd-local-rating'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/ftgd-local-rating',
                '/pm/config/adom/{adom}/obj/webfilter/ftgd-local-rating/{ftgd-local-rating}',
                '/pm/config/global/obj/webfilter/ftgd-local-rating',
                '/pm/config/global/obj/webfilter/ftgd-local-rating/{ftgd-local-rating}'
            ]
        },
        'webfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}',
                '/pm/config/global/obj/webfilter/profile',
                '/pm/config/global/obj/webfilter/profile/{profile}'
            ]
        },
        'webfilter_profile_antiphish': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish',
                '/pm/config/global/obj/webfilter/profile/{profile}/antiphish'
            ],
            'v_range': [['6.4.0', '']]
        },
        'webfilter_profile_antiphish_custompatterns': {
            'params': ['adom', 'custom-patterns', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish/custom-patterns',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish/custom-patterns/{custom-patterns}',
                '/pm/config/global/obj/webfilter/profile/{profile}/antiphish/custom-patterns',
                '/pm/config/global/obj/webfilter/profile/{profile}/antiphish/custom-patterns/{custom-patterns}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'webfilter_profile_antiphish_inspectionentries': {
            'params': ['adom', 'inspection-entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish/inspection-entries',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish/inspection-entries/{inspection-entries}',
                '/pm/config/global/obj/webfilter/profile/{profile}/antiphish/inspection-entries',
                '/pm/config/global/obj/webfilter/profile/{profile}/antiphish/inspection-entries/{inspection-entries}'
            ],
            'v_range': [['6.4.0', '']]
        },
        'webfilter_profile_filefilter': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/file-filter',
                '/pm/config/global/obj/webfilter/profile/{profile}/file-filter'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'webfilter_profile_filefilter_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/file-filter/entries',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/global/obj/webfilter/profile/{profile}/file-filter/entries',
                '/pm/config/global/obj/webfilter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'webfilter_profile_ftgdwf': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf'
            ]
        },
        'webfilter_profile_ftgdwf_filters': {
            'params': ['adom', 'filters', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/filters',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/filters/{filters}',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/filters',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/filters/{filters}'
            ]
        },
        'webfilter_profile_ftgdwf_quota': {
            'params': ['adom', 'profile', 'quota'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/quota',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/quota/{quota}',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/quota',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/quota/{quota}'
            ]
        },
        'webfilter_profile_ftgdwf_risk': {
            'params': ['adom', 'profile', 'risk'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/risk',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/risk/{risk}',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/risk',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/risk/{risk}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'webfilter_profile_override': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/override',
                '/pm/config/global/obj/webfilter/profile/{profile}/override'
            ]
        },
        'webfilter_profile_urlextraction': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/url-extraction',
                '/pm/config/global/obj/webfilter/profile/{profile}/url-extraction'
            ]
        },
        'webfilter_profile_web': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/web',
                '/pm/config/global/obj/webfilter/profile/{profile}/web'
            ]
        },
        'webfilter_profile_youtubechannelfilter': {
            'params': ['adom', 'profile', 'youtube-channel-filter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/youtube-channel-filter',
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/youtube-channel-filter/{youtube-channel-filter}',
                '/pm/config/global/obj/webfilter/profile/{profile}/youtube-channel-filter',
                '/pm/config/global/obj/webfilter/profile/{profile}/youtube-channel-filter/{youtube-channel-filter}'
            ]
        },
        'webfilter_urlfilter': {
            'params': ['adom', 'urlfilter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/urlfilter',
                '/pm/config/adom/{adom}/obj/webfilter/urlfilter/{urlfilter}',
                '/pm/config/global/obj/webfilter/urlfilter',
                '/pm/config/global/obj/webfilter/urlfilter/{urlfilter}'
            ]
        },
        'webfilter_urlfilter_entries': {
            'params': ['adom', 'entries', 'urlfilter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/urlfilter/{urlfilter}/entries',
                '/pm/config/adom/{adom}/obj/webfilter/urlfilter/{urlfilter}/entries/{entries}',
                '/pm/config/global/obj/webfilter/urlfilter/{urlfilter}/entries',
                '/pm/config/global/obj/webfilter/urlfilter/{urlfilter}/entries/{entries}'
            ]
        },
        'webproxy_forwardserver': {
            'params': ['adom', 'forward-server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server',
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server/{forward-server}',
                '/pm/config/global/obj/web-proxy/forward-server',
                '/pm/config/global/obj/web-proxy/forward-server/{forward-server}'
            ]
        },
        'webproxy_forwardservergroup': {
            'params': ['adom', 'forward-server-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server-group',
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{forward-server-group}',
                '/pm/config/global/obj/web-proxy/forward-server-group',
                '/pm/config/global/obj/web-proxy/forward-server-group/{forward-server-group}'
            ]
        },
        'webproxy_forwardservergroup_serverlist': {
            'params': ['adom', 'forward-server-group', 'server-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{forward-server-group}/server-list',
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{forward-server-group}/server-list/{server-list}',
                '/pm/config/global/obj/web-proxy/forward-server-group/{forward-server-group}/server-list',
                '/pm/config/global/obj/web-proxy/forward-server-group/{forward-server-group}/server-list/{server-list}'
            ]
        },
        'webproxy_isolatorserver': {
            'params': ['adom', 'isolator-server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/isolator-server',
                '/pm/config/adom/{adom}/obj/web-proxy/isolator-server/{isolator-server}',
                '/pm/config/global/obj/web-proxy/isolator-server',
                '/pm/config/global/obj/web-proxy/isolator-server/{isolator-server}'
            ],
            'v_range': [['7.6.2', '']]
        },
        'webproxy_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/profile',
                '/pm/config/adom/{adom}/obj/web-proxy/profile/{profile}',
                '/pm/config/global/obj/web-proxy/profile',
                '/pm/config/global/obj/web-proxy/profile/{profile}'
            ]
        },
        'webproxy_profile_headers': {
            'params': ['adom', 'headers', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/profile/{profile}/headers',
                '/pm/config/adom/{adom}/obj/web-proxy/profile/{profile}/headers/{headers}',
                '/pm/config/global/obj/web-proxy/profile/{profile}/headers',
                '/pm/config/global/obj/web-proxy/profile/{profile}/headers/{headers}'
            ]
        },
        'webproxy_wisp': {
            'params': ['adom', 'wisp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/wisp',
                '/pm/config/adom/{adom}/obj/web-proxy/wisp/{wisp}',
                '/pm/config/global/obj/web-proxy/wisp',
                '/pm/config/global/obj/web-proxy/wisp/{wisp}'
            ]
        },
        'widsprofile': {
            'params': ['adom', 'wids-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wids-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/wids-profile/{wids-profile}',
                '/pm/config/global/obj/wireless-controller/wids-profile',
                '/pm/config/global/obj/wireless-controller/wids-profile/{wids-profile}'
            ]
        },
        'wireless_accesscontrollist': {
            'params': ['access-control-list', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}',
                '/pm/config/global/obj/wireless-controller/access-control-list',
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'wireless_accesscontrollist_layer3ipv4rules': {
            'params': ['access-control-list', 'adom', 'layer3-ipv4-rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules',
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}',
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules',
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'wireless_accesscontrollist_layer3ipv6rules': {
            'params': ['access-control-list', 'adom', 'layer3-ipv6-rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules',
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}',
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules',
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'wireless_address': {
            'params': ['address', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/address',
                '/pm/config/adom/{adom}/obj/wireless-controller/address/{address}',
                '/pm/config/global/obj/wireless-controller/address',
                '/pm/config/global/obj/wireless-controller/address/{address}'
            ],
            'v_range': [['7.0.1', '']]
        },
        'wireless_addrgrp': {
            'params': ['addrgrp', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/addrgrp',
                '/pm/config/adom/{adom}/obj/wireless-controller/addrgrp/{addrgrp}',
                '/pm/config/global/obj/wireless-controller/addrgrp',
                '/pm/config/global/obj/wireless-controller/addrgrp/{addrgrp}'
            ],
            'v_range': [['7.0.1', '']]
        },
        'wireless_ssidpolicy': {
            'params': ['adom', 'ssid-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/ssid-policy',
                '/pm/config/adom/{adom}/obj/wireless-controller/ssid-policy/{ssid-policy}',
                '/pm/config/global/obj/wireless-controller/ssid-policy',
                '/pm/config/global/obj/wireless-controller/ssid-policy/{ssid-policy}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'wireless_syslogprofile': {
            'params': ['adom', 'syslog-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/syslog-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/syslog-profile/{syslog-profile}',
                '/pm/config/global/obj/wireless-controller/syslog-profile',
                '/pm/config/global/obj/wireless-controller/syslog-profile/{syslog-profile}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'wireless_vap_ip6prefixlist': {
            'params': ['adom', 'ip6-prefix-list', 'vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/ip6-prefix-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/ip6-prefix-list/{ip6-prefix-list}'
            ],
            'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']]
        },
        'wtpprofile': {
            'params': ['adom', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile',
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}',
                '/pm/config/global/obj/wireless-controller/wtp-profile',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}'
            ]
        },
        'wtpprofile_denymaclist': {
            'params': ['adom', 'deny-mac-list', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list',
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}'
            ]
        },
        'wtpprofile_eslsesdongle': {
            'params': ['adom', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/esl-ses-dongle',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/esl-ses-dongle'
            ],
            'v_range': [['7.0.1', '']]
        },
        'wtpprofile_lan': {
            'params': ['adom', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/lan',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/lan'
            ]
        },
        'wtpprofile_lbs': {
            'params': ['adom', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/lbs',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/lbs'
            ]
        },
        'wtpprofile_platform': {
            'params': ['adom', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/platform',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/platform'
            ]
        },
        'wtpprofile_radio1': {
            'params': ['adom', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-1',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-1'
            ]
        },
        'wtpprofile_radio2': {
            'params': ['adom', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-2',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-2'
            ]
        },
        'wtpprofile_radio3': {
            'params': ['adom', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-3',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-3'
            ],
            'v_range': [['6.2.2', '']]
        },
        'wtpprofile_radio4': {
            'params': ['adom', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-4',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/radio-4'
            ],
            'v_range': [['6.2.5', '']]
        },
        'wtpprofile_splittunnelingacl': {
            'params': ['adom', 'split-tunneling-acl', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl',
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}'
            ]
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
        'facts': {
            'required': True,
            'type': 'dict',
            'options': {
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': list(facts_metadata.keys())
                },
                'fields': {'type': 'list', 'elements': 'raw'},
                'filter': {'type': 'list', 'elements': 'raw'},
                'option': {'type': 'raw'},
                'sortings': {'type': 'list', 'elements': 'raw'},
                'params': {'type': 'dict'},
                'extra_params': {'type': 'dict'}
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec, supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('facts', facts_metadata, None, None, None, module, connection)
    fmgr.process_task()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
