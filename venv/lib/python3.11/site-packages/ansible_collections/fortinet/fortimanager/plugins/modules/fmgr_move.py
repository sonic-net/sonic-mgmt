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
module: fmgr_move
short_description: Move fortimanager defined Object.
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
        description: Access token of forticloud managed API users, this option is available with FortiManager later than 6.4.0.
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
    move:
        description: Reorder Two Objects.
        type: dict
        required: true
        suboptions:
            action:
                required: true
                description: Direction to indicate where to move an object entry.
                type: str
                choices:
                    - after
                    - before
            selector:
                required: true
                description: Selector of the move object.
                type: str
                choices:
                    - 'apcfgprofile_commandlist'
                    - 'application_casi_profile_entries'
                    - 'application_list_defaultnetworkservices'
                    - 'application_list_entries'
                    - 'application_list_entries_parameters'
                    - 'bonjourprofile_policylist'
                    - 'casb_profile'
                    - 'casb_saasapplication'
                    - 'casb_useractivity'
                    - 'cifs_profile_filefilter_entries'
                    - 'dlp_dictionary_entries'
                    - 'dlp_exactdatamatch_columns'
                    - 'dlp_filepattern_entries'
                    - 'dlp_label_entries'
                    - 'dlp_profile_rule'
                    - 'dlp_sensor_entries'
                    - 'dlp_sensor_filter'
                    - 'dnsfilter_domainfilter_entries'
                    - 'dnsfilter_urlfilter_entries'
                    - 'emailfilter_blockallowlist_entries'
                    - 'emailfilter_bwl_entries'
                    - 'emailfilter_bword_entries'
                    - 'emailfilter_profile_filefilter_entries'
                    - 'endpointcontrol_fctems'
                    - 'extendercontroller_extenderprofile_cellular_smsnotification_receiver'
                    - 'extendercontroller_extenderprofile_lanextension_backhaul'
                    - 'extensioncontroller_extenderprofile_cellular_smsnotification_receiver'
                    - 'extensioncontroller_extenderprofile_lanextension_backhaul'
                    - 'filefilter_profile_rules'
                    - 'firewall_accessproxy'
                    - 'firewall_accessproxy6'
                    - 'firewall_accessproxysshclientcert'
                    - 'firewall_accessproxyvirtualhost'
                    - 'firewall_carrierendpointbwl_entries'
                    - 'firewall_casbprofile'
                    - 'firewall_identitybasedroute'
                    - 'firewall_profileprotocoloptions_cifs_filefilter_entries'
                    - 'firewall_service_category'
                    - 'firewall_service_custom'
                    - 'firewall_shapingprofile_shapingentries'
                    - 'firewall_vip'
                    - 'firewall_vip6'
                    - 'ips_sensor_entries'
                    - 'ips_sensor_filter'
                    - 'mpskprofile_mpskgroup'
                    - 'mpskprofile_mpskgroup_mpskkey'
                    - 'pkg_authentication_rule'
                    - 'pkg_central_dnat'
                    - 'pkg_central_dnat6'
                    - 'pkg_firewall_acl'
                    - 'pkg_firewall_acl6'
                    - 'pkg_firewall_centralsnatmap'
                    - 'pkg_firewall_consolidated_policy'
                    - 'pkg_firewall_dospolicy'
                    - 'pkg_firewall_dospolicy6'
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
                    - 'pkg_firewall_proxypolicy'
                    - 'pkg_firewall_securitypolicy'
                    - 'pkg_firewall_shapingpolicy'
                    - 'pkg_user_nacpolicy'
                    - 'pm_config_pblock_firewall_consolidated_policy'
                    - 'pm_config_pblock_firewall_policy'
                    - 'pm_config_pblock_firewall_policy6'
                    - 'pm_config_pblock_firewall_proxypolicy'
                    - 'pm_config_pblock_firewall_securitypolicy'
                    - 'spamfilter_bwl_entries'
                    - 'spamfilter_bword_entries'
                    - 'sshfilter_profile_filefilter_entries'
                    - 'sshfilter_profile_shellcommands'
                    - 'switchcontroller_dynamicportpolicy_policy'
                    - 'switchcontroller_managedswitch'
                    - 'system_externalresource'
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
                    - 'user_deviceaccesslist_devicelist'
                    - 'vap_vlanname'
                    - 'videofilter_profile_filters'
                    - 'videofilter_profile_fortiguardcategory_filters'
                    - 'videofilter_youtubechannelfilter_entries'
                    - 'vpn_ipsec_fec_mappings'
                    - 'vpn_ssl_settings_authenticationrule'
                    - 'vpnsslweb_portal_bookmarkgroup'
                    - 'vpnsslweb_portal_bookmarkgroup_bookmarks'
                    - 'vpnsslweb_portal_splitdns'
                    - 'wanprof_system_sdwan_members'
                    - 'wanprof_system_sdwan_service'
                    - 'wanprof_system_sdwan_service_sla'
                    - 'wanprof_system_sdwan_zone'
                    - 'wanprof_system_virtualwanlink_members'
                    - 'wanprof_system_virtualwanlink_service'
                    - 'wanprof_system_virtualwanlink_service_sla'
                    - 'webfilter_contentheader_entries'
                    - 'webfilter_profile_filefilter_entries'
                    - 'webfilter_urlfilter_entries'
                    - 'wireless_accesscontrollist_layer3ipv4rules'
                    - 'wireless_accesscontrollist_layer3ipv6rules'
            self:
                required: true
                description: The parameter for each selector.
                type: dict
            target:
                required: true
                description: Key to the target entry.
                type: str
'''

EXAMPLES = '''
- name: Move an object
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Move a firewall vip object
      fortinet.fortimanager.fmgr_move:
        move:
          selector: "firewall_vip"
          target: "ansible-test-vip_first"
          action: "before"
          self:
            adom: "root"
            vip: "ansible-test-vip_second"
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
    move_metadata = {
        'apcfgprofile_commandlist': {
            'params': ['adom', 'apcfg-profile', 'command-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}',
                '/pm/config/global/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}'
            ],
            'v_range': [['6.4.6', '']]
        },
        'application_casi_profile_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/casi/profile/{profile}/entries/{entries}',
                '/pm/config/global/obj/application/casi/profile/{profile}/entries/{entries}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'application_list_defaultnetworkservices': {
            'params': ['adom', 'default-network-services', 'list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/default-network-services/{default-network-services}',
                '/pm/config/global/obj/application/list/{list}/default-network-services/{default-network-services}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'application_list_entries': {
            'params': ['adom', 'entries', 'list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}'
            ]
        },
        'application_list_entries_parameters': {
            'params': ['adom', 'entries', 'list', 'parameters'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}/parameters/{parameters}',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}/parameters/{parameters}'
            ]
        },
        'bonjourprofile_policylist': {
            'params': ['adom', 'bonjour-profile', 'policy-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}',
                '/pm/config/global/obj/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}'
            ]
        },
        'casb_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}',
                '/pm/config/global/obj/casb/profile/{profile}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_saasapplication': {
            'params': ['adom', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/saas-application/{saas-application}',
                '/pm/config/global/obj/casb/saas-application/{saas-application}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'casb_useractivity': {
            'params': ['adom', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}',
                '/pm/config/global/obj/casb/user-activity/{user-activity}'
            ],
            'v_range': [['7.4.1', '']]
        },
        'cifs_profile_filefilter_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/global/obj/cifs/profile/{profile}/file-filter/entries/{entries}'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'dlp_dictionary_entries': {
            'params': ['adom', 'dictionary', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/dictionary/{dictionary}/entries/{entries}',
                '/pm/config/global/obj/dlp/dictionary/{dictionary}/entries/{entries}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'dlp_exactdatamatch_columns': {
            'params': ['adom', 'columns', 'exact-data-match'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/exact-data-match/{exact-data-match}/columns/{columns}',
                '/pm/config/global/obj/dlp/exact-data-match/{exact-data-match}/columns/{columns}'
            ],
            'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']]
        },
        'dlp_filepattern_entries': {
            'params': ['adom', 'entries', 'filepattern'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/filepattern/{filepattern}/entries/{entries}',
                '/pm/config/global/obj/dlp/filepattern/{filepattern}/entries/{entries}'
            ]
        },
        'dlp_label_entries': {
            'params': ['adom', 'entries', 'label'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/label/{label}/entries/{entries}',
                '/pm/config/global/obj/dlp/label/{label}/entries/{entries}'
            ],
            'v_range': [['7.6.3', '']]
        },
        'dlp_profile_rule': {
            'params': ['adom', 'profile', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/profile/{profile}/rule/{rule}',
                '/pm/config/global/obj/dlp/profile/{profile}/rule/{rule}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'dlp_sensor_entries': {
            'params': ['adom', 'entries', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/dlp/sensor/{sensor}/entries/{entries}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'dlp_sensor_filter': {
            'params': ['adom', 'filter', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/dlp/sensor/{sensor}/filter/{filter}'
            ]
        },
        'dnsfilter_domainfilter_entries': {
            'params': ['adom', 'domain-filter', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{domain-filter}/entries/{entries}',
                '/pm/config/global/obj/dnsfilter/domain-filter/{domain-filter}/entries/{entries}'
            ]
        },
        'dnsfilter_urlfilter_entries': {
            'params': ['adom', 'entries', 'urlfilter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/urlfilter/{urlfilter}/entries/{entries}',
                '/pm/config/global/obj/dnsfilter/urlfilter/{urlfilter}/entries/{entries}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'emailfilter_blockallowlist_entries': {
            'params': ['adom', 'block-allow-list', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/block-allow-list/{block-allow-list}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/block-allow-list/{block-allow-list}/entries/{entries}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'emailfilter_bwl_entries': {
            'params': ['adom', 'bwl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/bwl/{bwl}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/bwl/{bwl}/entries/{entries}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_bword_entries': {
            'params': ['adom', 'bword', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/bword/{bword}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/bword/{bword}/entries/{entries}'
            ],
            'v_range': [['6.2.0', '']]
        },
        'emailfilter_profile_filefilter_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/global/obj/emailfilter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'endpointcontrol_fctems': {
            'params': ['adom', 'fctems'],
            'urls': [
                '/pm/config/adom/{adom}/obj/endpoint-control/fctems/{fctems}',
                '/pm/config/global/obj/endpoint-control/fctems/{fctems}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_cellular_smsnotification_receiver': {
            'params': ['adom', 'extender-profile', 'receiver'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_lanextension_backhaul': {
            'params': ['adom', 'backhaul', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'extensioncontroller_extenderprofile_cellular_smsnotification_receiver': {
            'params': ['adom', 'extender-profile', 'receiver'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_lanextension_backhaul': {
            'params': ['adom', 'backhaul', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'filefilter_profile_rules': {
            'params': ['adom', 'profile', 'rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/file-filter/profile/{profile}/rules/{rules}',
                '/pm/config/global/obj/file-filter/profile/{profile}/rules/{rules}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'firewall_accessproxy': {
            'params': ['access-proxy', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxy6': {
            'params': ['access-proxy6', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxysshclientcert': {
            'params': ['access-proxy-ssh-client-cert', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}',
                '/pm/config/global/obj/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'firewall_accessproxyvirtualhost': {
            'params': ['access-proxy-virtual-host', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-virtual-host/{access-proxy-virtual-host}',
                '/pm/config/global/obj/firewall/access-proxy-virtual-host/{access-proxy-virtual-host}'
            ],
            'v_range': [['7.0.1', '']]
        },
        'firewall_carrierendpointbwl_entries': {
            'params': ['adom', 'carrier-endpoint-bwl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries/{entries}',
                '/pm/config/global/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries/{entries}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'firewall_casbprofile': {
            'params': ['adom', 'casb-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}'
            ],
            'v_range': [['7.4.1', '7.4.1']]
        },
        'firewall_identitybasedroute': {
            'params': ['adom', 'identity-based-route'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/identity-based-route/{identity-based-route}',
                '/pm/config/global/obj/firewall/identity-based-route/{identity-based-route}'
            ]
        },
        'firewall_profileprotocoloptions_cifs_filefilter_entries': {
            'params': ['adom', 'entries', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries/{entries}',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries/{entries}'
            ],
            'v_range': [['6.4.2', '']]
        },
        'firewall_service_category': {
            'params': ['adom', 'category'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/category/{category}',
                '/pm/config/global/obj/firewall/service/category/{category}'
            ]
        },
        'firewall_service_custom': {
            'params': ['adom', 'custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/custom/{custom}',
                '/pm/config/global/obj/firewall/service/custom/{custom}'
            ]
        },
        'firewall_shapingprofile_shapingentries': {
            'params': ['adom', 'shaping-entries', 'shaping-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries/{shaping-entries}',
                '/pm/config/global/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries/{shaping-entries}'
            ]
        },
        'firewall_vip': {
            'params': ['adom', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}',
                '/pm/config/global/obj/firewall/vip/{vip}'
            ]
        },
        'firewall_vip6': {
            'params': ['adom', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}',
                '/pm/config/global/obj/firewall/vip6/{vip6}'
            ]
        },
        'ips_sensor_entries': {
            'params': ['adom', 'entries', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries/{entries}'
            ]
        },
        'ips_sensor_filter': {
            'params': ['adom', 'filter', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/ips/sensor/{sensor}/filter/{filter}'
            ],
            'v_range': [['6.0.0', '6.2.0']]
        },
        'mpskprofile_mpskgroup': {
            'params': ['adom', 'mpsk-group', 'mpsk-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}',
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}'
            ],
            'v_range': [['6.4.2', '']]
        },
        'mpskprofile_mpskgroup_mpskkey': {
            'params': ['adom', 'mpsk-group', 'mpsk-key', 'mpsk-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}',
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}'
            ],
            'v_range': [['6.4.2', '']]
        },
        'pkg_authentication_rule': {
            'params': ['adom', 'pkg', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/authentication/rule/{rule}'
            ],
            'v_range': [['6.2.1', '']]
        },
        'pkg_central_dnat': {
            'params': ['adom', 'dnat', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/central/dnat/{dnat}'
            ]
        },
        'pkg_central_dnat6': {
            'params': ['adom', 'dnat6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/central/dnat6/{dnat6}'
            ],
            'v_range': [['6.4.2', '']]
        },
        'pkg_firewall_acl': {
            'params': ['acl', 'adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl/{acl}'
            ],
            'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_acl6': {
            'params': ['acl6', 'adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl6/{acl6}'
            ],
            'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_centralsnatmap': {
            'params': ['adom', 'central-snat-map', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/central-snat-map/{central-snat-map}'
            ]
        },
        'pkg_firewall_consolidated_policy': {
            'params': ['adom', 'pkg', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/consolidated/policy/{policy}'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'pkg_firewall_dospolicy': {
            'params': ['DoS-policy', 'adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy/{DoS-policy}'
            ]
        },
        'pkg_firewall_dospolicy6': {
            'params': ['DoS-policy6', 'adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6/{DoS-policy6}'
            ]
        },
        'pkg_firewall_explicitproxypolicy': {
            'params': ['adom', 'explicit-proxy-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/explicit-proxy-policy/{explicit-proxy-policy}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'pkg_firewall_explicitproxypolicy_identitybasedpolicy': {
            'params': ['adom', 'explicit-proxy-policy', 'identity-based-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/explicit-proxy-policy/{explicit-proxy-policy}/identity-based-policy/{identity-based-policy}'
            ],
            'v_range': [['6.2.0', '6.2.13']]
        },
        'pkg_firewall_hyperscalepolicy': {
            'params': ['adom', 'hyperscale-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy/{hyperscale-policy}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_hyperscalepolicy46': {
            'params': ['adom', 'hyperscale-policy46', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy46/{hyperscale-policy46}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_hyperscalepolicy6': {
            'params': ['adom', 'hyperscale-policy6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy6/{hyperscale-policy6}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']]
        },
        'pkg_firewall_hyperscalepolicy64': {
            'params': ['adom', 'hyperscale-policy64', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy64/{hyperscale-policy64}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_interfacepolicy': {
            'params': ['adom', 'interface-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy/{interface-policy}'
            ],
            'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_interfacepolicy6': {
            'params': ['adom', 'interface-policy6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy6/{interface-policy6}'
            ],
            'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_localinpolicy': {
            'params': ['adom', 'local-in-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy/{local-in-policy}'
            ]
        },
        'pkg_firewall_localinpolicy6': {
            'params': ['adom', 'local-in-policy6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy6/{local-in-policy6}'
            ]
        },
        'pkg_firewall_multicastpolicy': {
            'params': ['adom', 'multicast-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy/{multicast-policy}'
            ]
        },
        'pkg_firewall_multicastpolicy6': {
            'params': ['adom', 'multicast-policy6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy6/{multicast-policy6}'
            ]
        },
        'pkg_firewall_policy': {
            'params': ['adom', 'pkg', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}'
            ]
        },
        'pkg_firewall_policy46': {
            'params': ['adom', 'pkg', 'policy46'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy46/{policy46}'
            ]
        },
        'pkg_firewall_policy6': {
            'params': ['adom', 'pkg', 'policy6'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy6/{policy6}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'pkg_firewall_policy64': {
            'params': ['adom', 'pkg', 'policy64'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy64/{policy64}'
            ]
        },
        'pkg_firewall_proxypolicy': {
            'params': ['adom', 'pkg', 'proxy-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/proxy-policy/{proxy-policy}'
            ]
        },
        'pkg_firewall_securitypolicy': {
            'params': ['adom', 'pkg', 'security-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/security-policy/{security-policy}'
            ],
            'v_range': [['6.2.1', '']]
        },
        'pkg_firewall_shapingpolicy': {
            'params': ['adom', 'pkg', 'shaping-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/shaping-policy/{shaping-policy}'
            ]
        },
        'pkg_user_nacpolicy': {
            'params': ['adom', 'nac-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/user/nac-policy/{nac-policy}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'pm_config_pblock_firewall_consolidated_policy': {
            'params': ['adom', 'pblock', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/consolidated/policy/{policy}'
            ],
            'v_range': [['7.0.3', '7.6.2']]
        },
        'pm_config_pblock_firewall_policy': {
            'params': ['adom', 'pblock', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy/{policy}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'pm_config_pblock_firewall_policy6': {
            'params': ['adom', 'pblock', 'policy6'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy6/{policy6}'
            ],
            'v_range': [['7.0.3', '7.6.2']]
        },
        'pm_config_pblock_firewall_proxypolicy': {
            'params': ['adom', 'pblock', 'proxy-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/proxy-policy/{proxy-policy}'
            ],
            'v_range': [['7.6.0', '']]
        },
        'pm_config_pblock_firewall_securitypolicy': {
            'params': ['adom', 'pblock', 'security-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/security-policy/{security-policy}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'spamfilter_bwl_entries': {
            'params': ['adom', 'bwl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bwl/{bwl}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/bwl/{bwl}/entries/{entries}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_bword_entries': {
            'params': ['adom', 'bword', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bword/{bword}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/bword/{bword}/entries/{entries}'
            ],
            'v_range': [['6.0.0', '7.2.1']]
        },
        'sshfilter_profile_filefilter_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/global/obj/ssh-filter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'v_range': [['6.2.2', '7.6.2']]
        },
        'sshfilter_profile_shellcommands': {
            'params': ['adom', 'profile', 'shell-commands'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/shell-commands/{shell-commands}',
                '/pm/config/global/obj/ssh-filter/profile/{profile}/shell-commands/{shell-commands}'
            ]
        },
        'switchcontroller_dynamicportpolicy_policy': {
            'params': ['adom', 'dynamic-port-policy', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}',
                '/pm/config/global/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'switchcontroller_managedswitch': {
            'params': ['adom', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}'
            ]
        },
        'system_externalresource': {
            'params': ['adom', 'external-resource'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/external-resource/{external-resource}',
                '/pm/config/global/obj/system/external-resource/{external-resource}'
            ]
        },
        'system_sdnconnector_compartmentlist': {
            'params': ['adom', 'compartment-list', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/compartment-list/{compartment-list}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/compartment-list/{compartment-list}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'system_sdnconnector_externalaccountlist': {
            'params': ['adom', 'external-account-list', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-account-list/{external-account-list}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-account-list/{external-account-list}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'system_sdnconnector_externalip': {
            'params': ['adom', 'external-ip', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-ip/{external-ip}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-ip/{external-ip}'
            ]
        },
        'system_sdnconnector_forwardingrule': {
            'params': ['adom', 'forwarding-rule', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/forwarding-rule/{forwarding-rule}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/forwarding-rule/{forwarding-rule}'
            ],
            'v_range': [['7.0.2', '']]
        },
        'system_sdnconnector_gcpprojectlist': {
            'params': ['adom', 'gcp-project-list', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/gcp-project-list/{gcp-project-list}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/gcp-project-list/{gcp-project-list}'
            ],
            'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']]
        },
        'system_sdnconnector_nic': {
            'params': ['adom', 'nic', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic/{nic}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic/{nic}'
            ]
        },
        'system_sdnconnector_nic_ip': {
            'params': ['adom', 'ip', 'nic', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip/{ip}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip/{ip}'
            ]
        },
        'system_sdnconnector_ociregionlist': {
            'params': ['adom', 'oci-region-list', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/oci-region-list/{oci-region-list}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/oci-region-list/{oci-region-list}'
            ],
            'v_range': [['7.4.0', '']]
        },
        'system_sdnconnector_route': {
            'params': ['adom', 'route', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route/{route}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route/{route}'
            ]
        },
        'system_sdnconnector_routetable': {
            'params': ['adom', 'route-table', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}'
            ]
        },
        'system_sdnconnector_routetable_route': {
            'params': ['adom', 'route', 'route-table', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}/route/{route}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}/route/{route}'
            ]
        },
        'user_deviceaccesslist_devicelist': {
            'params': ['adom', 'device-access-list', 'device-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-access-list/{device-access-list}/device-list/{device-list}',
                '/pm/config/global/obj/user/device-access-list/{device-access-list}/device-list/{device-list}'
            ],
            'v_range': [['6.2.2', '7.2.1']]
        },
        'vap_vlanname': {
            'params': ['adom', 'vap', 'vlan-name'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/vlan-name/{vlan-name}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/vlan-name/{vlan-name}'
            ],
            'v_range': [['7.0.3', '']]
        },
        'videofilter_profile_filters': {
            'params': ['adom', 'filters', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/filters/{filters}',
                '/pm/config/global/obj/videofilter/profile/{profile}/filters/{filters}'
            ],
            'v_range': [['7.4.2', '']]
        },
        'videofilter_profile_fortiguardcategory_filters': {
            'params': ['adom', 'filters', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/fortiguard-category/filters/{filters}',
                '/pm/config/global/obj/videofilter/profile/{profile}/fortiguard-category/filters/{filters}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'videofilter_youtubechannelfilter_entries': {
            'params': ['adom', 'entries', 'youtube-channel-filter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}/entries/{entries}',
                '/pm/config/global/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}/entries/{entries}'
            ],
            'v_range': [['7.0.0', '']]
        },
        'vpn_ipsec_fec_mappings': {
            'params': ['adom', 'fec', 'mappings'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ipsec/fec/{fec}/mappings/{mappings}',
                '/pm/config/global/obj/vpn/ipsec/fec/{fec}/mappings/{mappings}'
            ],
            'v_range': [['7.2.0', '']]
        },
        'vpn_ssl_settings_authenticationrule': {
            'params': ['authentication-rule', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/authentication-rule/{authentication-rule}'
            ],
            'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']]
        },
        'vpnsslweb_portal_bookmarkgroup': {
            'params': ['adom', 'bookmark-group', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}'
            ]
        },
        'vpnsslweb_portal_bookmarkgroup_bookmarks': {
            'params': ['adom', 'bookmark-group', 'bookmarks', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}'
            ]
        },
        'vpnsslweb_portal_splitdns': {
            'params': ['adom', 'portal', 'split-dns'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/split-dns/{split-dns}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/split-dns/{split-dns}'
            ]
        },
        'wanprof_system_sdwan_members': {
            'params': ['adom', 'members', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/members/{members}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_service': {
            'params': ['adom', 'service', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/service/{service}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_service_sla': {
            'params': ['adom', 'service', 'sla', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/service/{service}/sla/{sla}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_zone': {
            'params': ['adom', 'wanprof', 'zone'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/zone/{zone}'
            ],
            'v_range': [['6.4.1', '']]
        },
        'wanprof_system_virtualwanlink_members': {
            'params': ['adom', 'members', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/members/{members}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_service': {
            'params': ['adom', 'service', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/service/{service}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_service_sla': {
            'params': ['adom', 'service', 'sla', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/service/{service}/sla/{sla}'
            ],
            'v_range': [['6.0.0', '7.6.2']]
        },
        'webfilter_contentheader_entries': {
            'params': ['adom', 'content-header', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content-header/{content-header}/entries/{entries}',
                '/pm/config/global/obj/webfilter/content-header/{content-header}/entries/{entries}'
            ]
        },
        'webfilter_profile_filefilter_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/global/obj/webfilter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'v_range': [['6.2.0', '7.6.2']]
        },
        'webfilter_urlfilter_entries': {
            'params': ['adom', 'entries', 'urlfilter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/urlfilter/{urlfilter}/entries/{entries}',
                '/pm/config/global/obj/webfilter/urlfilter/{urlfilter}/entries/{entries}'
            ]
        },
        'wireless_accesscontrollist_layer3ipv4rules': {
            'params': ['access-control-list', 'adom', 'layer3-ipv4-rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}',
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}'
            ],
            'v_range': [['7.2.1', '']]
        },
        'wireless_accesscontrollist_layer3ipv6rules': {
            'params': ['access-control-list', 'adom', 'layer3-ipv6-rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}',
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}'
            ],
            'v_range': [['7.2.1', '']]
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
        'move': {
            'required': True,
            'type': 'dict',
            'options': {
                'action': {'required': True, 'type': 'str', 'choices': ['after', 'before']},
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': list(move_metadata.keys())
                },
                'self': {'required': True, 'type': 'dict'},
                'target': {'required': True, 'type': 'str'}
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec, supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('move', move_metadata, None, None, None, module, connection)
    fmgr.process_task()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
