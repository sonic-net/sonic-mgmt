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
module: fmgr_pkg_firewall_securitypolicy
short_description: Configure NGFW IPv4/IPv6 application policies.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_firewall_securitypolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Policy action
                choices:
                    - 'deny'
                    - 'accept'
            app_category:
                aliases: ['app-category']
                type: raw
                description: (list or str) Application category ID list.
            app_group:
                aliases: ['app-group']
                type: raw
                description: (list or str) Application group names.
            application:
                type: raw
                description: (list) Application ID list.
            application_list:
                aliases: ['application-list']
                type: str
                description: Name of an existing Application list.
            av_profile:
                aliases: ['av-profile']
                type: str
                description: Name of an existing Antivirus profile.
            cifs_profile:
                aliases: ['cifs-profile']
                type: str
                description: Name of an existing CIFS profile.
            comments:
                type: str
                description: Comment.
            dlp_sensor:
                aliases: ['dlp-sensor']
                type: str
                description: Name of an existing DLP sensor.
            dnsfilter_profile:
                aliases: ['dnsfilter-profile']
                type: str
                description: Name of an existing DNS filter profile.
            dstaddr4:
                type: raw
                description: (list or str) Destination IPv4 address name and address group names.
            dstaddr6:
                type: raw
                description: (list or str) Destination IPv6 address name and address group names.
            dstintf:
                type: raw
                description: (list or str) Outgoing
            emailfilter_profile:
                aliases: ['emailfilter-profile']
                type: str
                description: Name of an existing email filter profile.
            enforce_default_app_port:
                aliases: ['enforce-default-app-port']
                type: str
                description: Enable/disable default application port enforcement for allowed applications.
                choices:
                    - 'disable'
                    - 'enable'
            groups:
                type: raw
                description: (list or str) Names of user groups that can authenticate with this policy.
            icap_profile:
                aliases: ['icap-profile']
                type: str
                description: Name of an existing ICAP profile.
            internet_service:
                aliases: ['internet-service']
                type: str
                description: Enable/disable use of Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_custom:
                aliases: ['internet-service-custom']
                type: raw
                description: (list or str) Custom Internet Service name.
            internet_service_custom_group:
                aliases: ['internet-service-custom-group']
                type: raw
                description: (list or str) Custom Internet Service group name.
            internet_service_group:
                aliases: ['internet-service-group']
                type: raw
                description: (list or str) Internet Service group name.
            internet_service_id:
                aliases: ['internet-service-id']
                type: raw
                description: (list or str) Internet Service ID.
            internet_service_negate:
                aliases: ['internet-service-negate']
                type: str
                description: When enabled internet-service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_src:
                aliases: ['internet-service-src']
                type: str
                description: Enable/disable use of Internet Services in source for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_src_custom:
                aliases: ['internet-service-src-custom']
                type: raw
                description: (list or str) Custom Internet Service source name.
            internet_service_src_custom_group:
                aliases: ['internet-service-src-custom-group']
                type: raw
                description: (list or str) Custom Internet Service source group name.
            internet_service_src_group:
                aliases: ['internet-service-src-group']
                type: raw
                description: (list or str) Internet Service source group name.
            internet_service_src_id:
                aliases: ['internet-service-src-id']
                type: raw
                description: (list or str) Internet Service source ID.
            internet_service_src_negate:
                aliases: ['internet-service-src-negate']
                type: str
                description: When enabled internet-service-src specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            ips_sensor:
                aliases: ['ips-sensor']
                type: str
                description: Name of an existing IPS sensor.
            logtraffic:
                type: str
                description: Enable or disable logging.
                choices:
                    - 'disable'
                    - 'all'
                    - 'utm'
            logtraffic_start:
                aliases: ['logtraffic-start']
                type: str
                description: Record logs when a session starts.
                choices:
                    - 'disable'
                    - 'enable'
            mms_profile:
                aliases: ['mms-profile']
                type: str
                description: Name of an existing MMS profile.
            name:
                type: str
                description: Policy name.
            policyid:
                type: int
                description: Policy ID.
                required: true
            profile_group:
                aliases: ['profile-group']
                type: str
                description: Name of profile group.
            profile_protocol_options:
                aliases: ['profile-protocol-options']
                type: str
                description: Name of an existing Protocol options profile.
            profile_type:
                aliases: ['profile-type']
                type: str
                description: Determine whether the firewall policy allows security profile groups or single profiles only.
                choices:
                    - 'single'
                    - 'group'
            schedule:
                type: str
                description: Schedule name.
            service:
                type: raw
                description: (list or str) Service and service group names.
            service_negate:
                aliases: ['service-negate']
                type: str
                description: When enabled service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr4:
                type: raw
                description: (list or str) Source IPv4 address name and address group names.
            srcaddr6:
                type: raw
                description: (list or str) Source IPv6 address name and address group names.
            srcintf:
                type: raw
                description: (list or str) Incoming
            ssh_filter_profile:
                aliases: ['ssh-filter-profile']
                type: str
                description: Name of an existing SSH filter profile.
            ssl_ssh_profile:
                aliases: ['ssl-ssh-profile']
                type: str
                description: Name of an existing SSL SSH profile.
            status:
                type: str
                description: Enable or disable this policy.
                choices:
                    - 'disable'
                    - 'enable'
            url_category:
                aliases: ['url-category']
                type: raw
                description: (list or str) URL category ID list.
            users:
                type: raw
                description: (list or str) Names of individual users that can authenticate with this policy.
            utm_status:
                aliases: ['utm-status']
                type: str
                description: Enable security profiles.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            voip_profile:
                aliases: ['voip-profile']
                type: str
                description: Name of an existing VoIP profile.
            webfilter_profile:
                aliases: ['webfilter-profile']
                type: str
                description: Name of an existing Web filter profile.
            fsso_groups:
                aliases: ['fsso-groups']
                type: raw
                description: (list or str) Names of FSSO groups.
            global_label:
                aliases: ['global-label']
                type: str
                description: Label for the policy that appears when the GUI is in Global View mode.
            send_deny_packet:
                aliases: ['send-deny-packet']
                type: str
                description: Enable to send a reply when a session is denied or blocked by a firewall policy.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                type: raw
                description: (list or str) Destination IPv4 address name and address group names.
            internet_service_name:
                aliases: ['internet-service-name']
                type: raw
                description: (list or str) Internet Service name.
            internet_service_src_name:
                aliases: ['internet-service-src-name']
                type: raw
                description: (list or str) Internet Service source name.
            srcaddr:
                type: raw
                description: (list or str) Source IPv4 address name and address group names.
            dstaddr_negate:
                aliases: ['dstaddr-negate']
                type: str
                description: When enabled dstaddr/dstaddr6 specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            file_filter_profile:
                aliases: ['file-filter-profile']
                type: str
                description: Name of an existing file-filter profile.
            srcaddr_negate:
                aliases: ['srcaddr-negate']
                type: str
                description: When enabled srcaddr/srcaddr6 specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            learning_mode:
                aliases: ['learning-mode']
                type: str
                description: Enable to allow everything, but log all of the meaningful data for security information gathering.
                choices:
                    - 'disable'
                    - 'enable'
            videofilter_profile:
                aliases: ['videofilter-profile']
                type: str
                description: Name of an existing VideoFilter profile.
            _policy_block:
                type: int
                description: Assigned policy block.
            dlp_profile:
                aliases: ['dlp-profile']
                type: str
                description: Name of an existing DLP profile.
            nat46:
                type: str
                description: Enable/disable NAT46.
                choices:
                    - 'disable'
                    - 'enable'
            nat64:
                type: str
                description: Enable/disable NAT64.
                choices:
                    - 'disable'
                    - 'enable'
            sctp_filter_profile:
                aliases: ['sctp-filter-profile']
                type: str
                description: Name of an existing SCTP filter profile.
            internet_service6:
                aliases: ['internet-service6']
                type: str
                description: Enable/disable use of IPv6 Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_custom:
                aliases: ['internet-service6-custom']
                type: raw
                description: (list) Custom IPv6 Internet Service name.
            internet_service6_custom_group:
                aliases: ['internet-service6-custom-group']
                type: raw
                description: (list) Custom IPv6 Internet Service group name.
            internet_service6_group:
                aliases: ['internet-service6-group']
                type: raw
                description: (list) Internet Service group name.
            internet_service6_name:
                aliases: ['internet-service6-name']
                type: raw
                description: (list) IPv6 Internet Service name.
            internet_service6_negate:
                aliases: ['internet-service6-negate']
                type: str
                description: When enabled internet-service6 specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_src:
                aliases: ['internet-service6-src']
                type: str
                description: Enable/disable use of IPv6 Internet Services in source for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_src_custom:
                aliases: ['internet-service6-src-custom']
                type: raw
                description: (list) Custom IPv6 Internet Service source name.
            internet_service6_src_custom_group:
                aliases: ['internet-service6-src-custom-group']
                type: raw
                description: (list) Custom Internet Service6 source group name.
            internet_service6_src_group:
                aliases: ['internet-service6-src-group']
                type: raw
                description: (list) Internet Service6 source group name.
            internet_service6_src_name:
                aliases: ['internet-service6-src-name']
                type: raw
                description: (list) IPv6 Internet Service source name.
            internet_service6_src_negate:
                aliases: ['internet-service6-src-negate']
                type: str
                description: When enabled internet-service6-src specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            casb_profile:
                aliases: ['casb-profile']
                type: str
                description: Name of an existing CASB profile.
            diameter_filter_profile:
                aliases: ['diameter-filter-profile']
                type: str
                description: Name of an existing Diameter filter profile.
            dstaddr6_negate:
                aliases: ['dstaddr6-negate']
                type: str
                description: When enabled dstaddr6 specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            ips_voip_filter:
                aliases: ['ips-voip-filter']
                type: str
                description: Name of an existing VoIP
            srcaddr6_negate:
                aliases: ['srcaddr6-negate']
                type: str
                description: When enabled srcaddr6 specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            virtual_patch_profile:
                aliases: ['virtual-patch-profile']
                type: str
                description: Name of an existing virtual-patch profile.
            telemetry_profile:
                aliases: ['telemetry-profile']
                type: raw
                description: (list) Name of an existing telemetry profile.
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
    - name: Configure NGFW IPv4/IPv6 application policies.
      fortinet.fortimanager.fmgr_pkg_firewall_securitypolicy:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        pkg: <your own value>
        state: present # <value in [present, absent]>
        pkg_firewall_securitypolicy:
          policyid: 0 # Required variable, integer
          # action: <value in [deny, accept]>
          # app_category: <list or string>
          # app_group: <list or string>
          # application: <list or integer>
          # application_list: <string>
          # av_profile: <string>
          # cifs_profile: <string>
          # comments: <string>
          # dlp_sensor: <string>
          # dnsfilter_profile: <string>
          # dstaddr4: <list or string>
          # dstaddr6: <list or string>
          # dstintf: <list or string>
          # emailfilter_profile: <string>
          # enforce_default_app_port: <value in [disable, enable]>
          # groups: <list or string>
          # icap_profile: <string>
          # internet_service: <value in [disable, enable]>
          # internet_service_custom: <list or string>
          # internet_service_custom_group: <list or string>
          # internet_service_group: <list or string>
          # internet_service_id: <list or string>
          # internet_service_negate: <value in [disable, enable]>
          # internet_service_src: <value in [disable, enable]>
          # internet_service_src_custom: <list or string>
          # internet_service_src_custom_group: <list or string>
          # internet_service_src_group: <list or string>
          # internet_service_src_id: <list or string>
          # internet_service_src_negate: <value in [disable, enable]>
          # ips_sensor: <string>
          # logtraffic: <value in [disable, all, utm]>
          # logtraffic_start: <value in [disable, enable]>
          # mms_profile: <string>
          # name: <string>
          # profile_group: <string>
          # profile_protocol_options: <string>
          # profile_type: <value in [single, group]>
          # schedule: <string>
          # service: <list or string>
          # service_negate: <value in [disable, enable]>
          # srcaddr4: <list or string>
          # srcaddr6: <list or string>
          # srcintf: <list or string>
          # ssh_filter_profile: <string>
          # ssl_ssh_profile: <string>
          # status: <value in [disable, enable]>
          # url_category: <list or string>
          # users: <list or string>
          # utm_status: <value in [disable, enable]>
          # uuid: <string>
          # voip_profile: <string>
          # webfilter_profile: <string>
          # fsso_groups: <list or string>
          # global_label: <string>
          # send_deny_packet: <value in [disable, enable]>
          # dstaddr: <list or string>
          # internet_service_name: <list or string>
          # internet_service_src_name: <list or string>
          # srcaddr: <list or string>
          # dstaddr_negate: <value in [disable, enable]>
          # file_filter_profile: <string>
          # srcaddr_negate: <value in [disable, enable]>
          # learning_mode: <value in [disable, enable]>
          # videofilter_profile: <string>
          # _policy_block: <integer>
          # dlp_profile: <string>
          # nat46: <value in [disable, enable]>
          # nat64: <value in [disable, enable]>
          # sctp_filter_profile: <string>
          # internet_service6: <value in [disable, enable]>
          # internet_service6_custom: <list or string>
          # internet_service6_custom_group: <list or string>
          # internet_service6_group: <list or string>
          # internet_service6_name: <list or string>
          # internet_service6_negate: <value in [disable, enable]>
          # internet_service6_src: <value in [disable, enable]>
          # internet_service6_src_custom: <list or string>
          # internet_service6_src_custom_group: <list or string>
          # internet_service6_src_group: <list or string>
          # internet_service6_src_name: <list or string>
          # internet_service6_src_negate: <value in [disable, enable]>
          # casb_profile: <string>
          # diameter_filter_profile: <string>
          # dstaddr6_negate: <value in [disable, enable]>
          # ips_voip_filter: <string>
          # srcaddr6_negate: <value in [disable, enable]>
          # virtual_patch_profile: <string>
          # telemetry_profile: <list or string>
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/security-policy'
    ]
    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_securitypolicy': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'action': {'v_range': [['6.2.1', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'app-category': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'app-group': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'application': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'application-list': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'av-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'cifs-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'comments': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'dlp-sensor': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'dnsfilter-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'dstaddr4': {'v_range': [['6.2.1', '7.6.2']], 'type': 'raw'},
                'dstaddr6': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'dstintf': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'emailfilter-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'enforce-default-app-port': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'groups': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'icap-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'internet-service': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-custom': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-custom-group': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-group': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-id': {'v_range': [['6.2.1', '7.6.2']], 'type': 'raw'},
                'internet-service-negate': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-custom': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-src-custom-group': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-src-group': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-src-id': {'v_range': [['6.2.1', '7.6.2']], 'type': 'raw'},
                'internet-service-src-negate': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-sensor': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'logtraffic': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'all', 'utm'], 'type': 'str'},
                'logtraffic-start': {'v_range': [['6.2.1', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-profile': {'v_range': [['6.2.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'name': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'policyid': {'v_range': [['6.2.1', '']], 'required': True, 'type': 'int'},
                'profile-group': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'profile-protocol-options': {'v_range': [['6.2.1', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'profile-type': {'v_range': [['6.2.1', '']], 'choices': ['single', 'group'], 'type': 'str'},
                'schedule': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'service': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'service-negate': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr4': {'v_range': [['6.2.1', '7.6.2']], 'type': 'raw'},
                'srcaddr6': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'srcintf': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'ssh-filter-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'ssl-ssh-profile': {'v_range': [['6.2.1', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'status': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'url-category': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'users': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'utm-status': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'voip-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'webfilter-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'fsso-groups': {'v_range': [['6.2.2', '']], 'type': 'raw'},
                'global-label': {'v_range': [['6.2.3', '']], 'type': 'str'},
                'send-deny-packet': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr': {'v_range': [['6.4.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service-name': {'v_range': [['6.4.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service-src-name': {'v_range': [['6.4.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'srcaddr': {'v_range': [['6.4.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'dstaddr-negate': {
                    'v_range': [['6.4.2', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'file-filter-profile': {'v_range': [['6.4.1', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'srcaddr-negate': {
                    'v_range': [['6.4.2', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'learning-mode': {
                    'v_range': [['7.0.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'videofilter-profile': {'v_range': [['7.0.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                '_policy_block': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'dlp-profile': {'v_range': [['7.2.0', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'nat46': {
                    'v_range': [['7.0.2', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'nat64': {
                    'v_range': [['7.0.2', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'sctp-filter-profile': {'v_range': [['7.0.1', '7.2.2'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'internet-service6': {
                    'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'internet-service6-custom': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-custom-group': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-group': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-name': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-negate': {
                    'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'internet-service6-src': {
                    'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'internet-service6-src-custom': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-src-custom-group': {
                    'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'type': 'raw'
                },
                'internet-service6-src-group': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-src-name': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-src-negate': {
                    'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'casb-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'diameter-filter-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'dstaddr6-negate': {'v_range': [['7.2.6', '7.2.11'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-voip-filter': {'v_range': [['7.2.6', '7.2.11'], ['7.4.2', '']], 'type': 'str'},
                'srcaddr6-negate': {'v_range': [['7.2.6', '7.2.11'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-patch-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'telemetry-profile': {'v_range': [['7.6.3', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_securitypolicy'),
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
