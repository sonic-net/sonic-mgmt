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
module: fmgr_pkg_firewall_explicitproxypolicy
short_description: Configure Explicit proxy policies.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    pkg_firewall_explicitproxypolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Policy action.
                choices:
                    - 'deny'
                    - 'accept'
            active_auth_method:
                aliases: ['active-auth-method']
                type: str
                description: Active authentication method.
                choices:
                    - 'ntlm'
                    - 'basic'
                    - 'digest'
                    - 'form'
                    - 'none'
                    - 'negotiate'
            application_list:
                aliases: ['application-list']
                type: str
                description: Application list.
            av_profile:
                aliases: ['av-profile']
                type: str
                description: Antivirus profile.
            casi_profile:
                aliases: ['casi-profile']
                type: str
                description: CASI profile.
            comments:
                type: str
                description: Comment.
            disclaimer:
                type: str
                description: Web proxy disclaimer setting.
                choices:
                    - 'disable'
                    - 'domain'
                    - 'policy'
                    - 'user'
            dlp_sensor:
                aliases: ['dlp-sensor']
                type: str
                description: DLP sensor.
            dstaddr:
                type: str
                description: Destination address name.
            dstaddr_negate:
                aliases: ['dstaddr-negate']
                type: str
                description: Enable/disable negated destination address match.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr6:
                type: str
                description: IPv6 destination address
            dstintf:
                type: str
                description: Destination interface name.
            global_label:
                aliases: ['global-label']
                type: str
                description: Label for global view.
            icap_profile:
                aliases: ['icap-profile']
                type: str
                description: ICAP profile.
            identity_based:
                aliases: ['identity-based']
                type: str
                description: Enable/disable identity-based policy.
                choices:
                    - 'disable'
                    - 'enable'
            identity_based_policy:
                aliases: ['identity-based-policy']
                type: list
                elements: dict
                description: Identity based policy.
                suboptions:
                    application_list:
                        aliases: ['application-list']
                        type: str
                        description: Application list.
                    av_profile:
                        aliases: ['av-profile']
                        type: str
                        description: Antivirus profile.
                    casi_profile:
                        aliases: ['casi-profile']
                        type: str
                        description: CASI profile.
                    disclaimer:
                        type: str
                        description: Web proxy disclaimer setting.
                        choices:
                            - 'disable'
                            - 'domain'
                            - 'policy'
                            - 'user'
                    dlp_sensor:
                        aliases: ['dlp-sensor']
                        type: str
                        description: DLP sensor.
                    groups:
                        type: str
                        description: Group name.
                    icap_profile:
                        aliases: ['icap-profile']
                        type: str
                        description: ICAP profile.
                    id:
                        type: int
                        description: ID.
                    ips_sensor:
                        aliases: ['ips-sensor']
                        type: str
                        description: IPS sensor.
                    logtraffic:
                        type: str
                        description: Enable/disable policy log traffic.
                        choices:
                            - 'disable'
                            - 'all'
                            - 'utm'
                    logtraffic_start:
                        aliases: ['logtraffic-start']
                        type: str
                        description: Enable/disable policy log traffic start.
                        choices:
                            - 'disable'
                            - 'enable'
                    mms_profile:
                        aliases: ['mms-profile']
                        type: str
                        description: Mms profile
                    profile_group:
                        aliases: ['profile-group']
                        type: str
                        description: Profile group
                    profile_protocol_options:
                        aliases: ['profile-protocol-options']
                        type: str
                        description: Profile protocol options.
                    profile_type:
                        aliases: ['profile-type']
                        type: str
                        description: Profile type
                        choices:
                            - 'single'
                            - 'group'
                    replacemsg_override_group:
                        aliases: ['replacemsg-override-group']
                        type: str
                        description: Specify authentication replacement message override group.
                    scan_botnet_connections:
                        aliases: ['scan-botnet-connections']
                        type: str
                        description: Enable/disable scanning of connections to Botnet servers.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    schedule:
                        type: str
                        description: Schedule name.
                    spamfilter_profile:
                        aliases: ['spamfilter-profile']
                        type: str
                        description: Spam filter profile.
                    ssl_ssh_profile:
                        aliases: ['ssl-ssh-profile']
                        type: str
                        description: SSL SSH Profile.
                    users:
                        type: str
                        description: User name.
                    utm_status:
                        aliases: ['utm-status']
                        type: str
                        description: Enable AV/web/IPS protection profile.
                        choices:
                            - 'disable'
                            - 'enable'
                    waf_profile:
                        aliases: ['waf-profile']
                        type: str
                        description: Web application firewall profile.
                    webfilter_profile:
                        aliases: ['webfilter-profile']
                        type: str
                        description: Web filter profile.
            ip_based:
                aliases: ['ip-based']
                type: str
                description: Enable/disable IP-based authentication.
                choices:
                    - 'disable'
                    - 'enable'
            ips_sensor:
                aliases: ['ips-sensor']
                type: str
                description: IPS sensor.
            label:
                type: str
                description: Label for section view.
            logtraffic:
                type: str
                description: Enable/disable policy log traffic.
                choices:
                    - 'disable'
                    - 'all'
                    - 'utm'
            logtraffic_start:
                aliases: ['logtraffic-start']
                type: str
                description: Enable/disable policy log traffic start.
                choices:
                    - 'disable'
                    - 'enable'
            mms_profile:
                aliases: ['mms-profile']
                type: str
                description: Mms profile
            policyid:
                type: int
                description: Policy ID.
                required: true
            profile_group:
                aliases: ['profile-group']
                type: str
                description: Profile group
            profile_protocol_options:
                aliases: ['profile-protocol-options']
                type: str
                description: Profile protocol options.
            profile_type:
                aliases: ['profile-type']
                type: str
                description: Profile type
                choices:
                    - 'single'
                    - 'group'
            proxy:
                type: str
                description: Explicit proxy type.
                choices:
                    - 'web'
                    - 'ftp'
                    - 'wanopt'
            replacemsg_override_group:
                aliases: ['replacemsg-override-group']
                type: str
                description: Specify authentication replacement message override group.
            require_tfa:
                aliases: ['require-tfa']
                type: str
                description: Enable/disable requirement of 2-factor authentication.
                choices:
                    - 'disable'
                    - 'enable'
            scan_botnet_connections:
                aliases: ['scan-botnet-connections']
                type: str
                description: Enable/disable scanning of connections to Botnet servers.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            schedule:
                type: str
                description: Schedule name.
            service:
                type: str
                description: Service name.
            service_negate:
                aliases: ['service-negate']
                type: str
                description: Enable/disable negated service match.
                choices:
                    - 'disable'
                    - 'enable'
            spamfilter_profile:
                aliases: ['spamfilter-profile']
                type: str
                description: Spam filter profile.
            srcaddr:
                type: str
                description: Source address name.
            srcaddr_negate:
                aliases: ['srcaddr-negate']
                type: str
                description: Enable/disable negated source address match.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr6:
                type: str
                description: IPv6 source address
            ssl_ssh_profile:
                aliases: ['ssl-ssh-profile']
                type: str
                description: SSL SSH Profile.
            sso_auth_method:
                aliases: ['sso-auth-method']
                type: str
                description: SSO authentication method.
                choices:
                    - 'fsso'
                    - 'rsso'
                    - 'none'
            status:
                type: str
                description: Enable/disable policy status.
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: str
                description: Applied object tags.
            transaction_based:
                aliases: ['transaction-based']
                type: str
                description: Enable/disable transaction based authentication.
                choices:
                    - 'disable'
                    - 'enable'
            transparent:
                type: str
                description: Use IP address of client to connect to server.
                choices:
                    - 'disable'
                    - 'enable'
            utm_status:
                aliases: ['utm-status']
                type: str
                description: Enable AV/web/IPS protection profile.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique IDentifier.
            waf_profile:
                aliases: ['waf-profile']
                type: str
                description: Web application firewall profile.
            web_auth_cookie:
                aliases: ['web-auth-cookie']
                type: str
                description: Enable/disable Web authentication cookie.
                choices:
                    - 'disable'
                    - 'enable'
            webcache:
                type: str
                description: Enable/disable web cache.
                choices:
                    - 'disable'
                    - 'enable'
            webcache_https:
                aliases: ['webcache-https']
                type: str
                description: Enable/disable web cache for HTTPS.
                choices:
                    - 'disable'
                    - 'any'
                    - 'enable'
            webfilter_profile:
                aliases: ['webfilter-profile']
                type: str
                description: Web filter profile.
            webproxy_forward_server:
                aliases: ['webproxy-forward-server']
                type: str
                description: Web proxy forward server.
            webproxy_profile:
                aliases: ['webproxy-profile']
                type: str
                description: Web proxy profile.
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
    - name: Configure Explicit proxy policies.
      fortinet.fortimanager.fmgr_pkg_firewall_explicitproxypolicy:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        pkg: <your own value>
        state: present # <value in [present, absent]>
        pkg_firewall_explicitproxypolicy:
          policyid: 0 # Required variable, integer
          # action: <value in [deny, accept]>
          # active_auth_method: <value in [ntlm, basic, digest, ...]>
          # application_list: <string>
          # av_profile: <string>
          # casi_profile: <string>
          # comments: <string>
          # disclaimer: <value in [disable, domain, policy, ...]>
          # dlp_sensor: <string>
          # dstaddr: <string>
          # dstaddr_negate: <value in [disable, enable]>
          # dstaddr6: <string>
          # dstintf: <string>
          # global_label: <string>
          # icap_profile: <string>
          # identity_based: <value in [disable, enable]>
          # identity_based_policy:
          #   - application_list: <string>
          #     av_profile: <string>
          #     casi_profile: <string>
          #     disclaimer: <value in [disable, domain, policy, ...]>
          #     dlp_sensor: <string>
          #     groups: <string>
          #     icap_profile: <string>
          #     id: <integer>
          #     ips_sensor: <string>
          #     logtraffic: <value in [disable, all, utm]>
          #     logtraffic_start: <value in [disable, enable]>
          #     mms_profile: <string>
          #     profile_group: <string>
          #     profile_protocol_options: <string>
          #     profile_type: <value in [single, group]>
          #     replacemsg_override_group: <string>
          #     scan_botnet_connections: <value in [disable, block, monitor]>
          #     schedule: <string>
          #     spamfilter_profile: <string>
          #     ssl_ssh_profile: <string>
          #     users: <string>
          #     utm_status: <value in [disable, enable]>
          #     waf_profile: <string>
          #     webfilter_profile: <string>
          # ip_based: <value in [disable, enable]>
          # ips_sensor: <string>
          # label: <string>
          # logtraffic: <value in [disable, all, utm]>
          # logtraffic_start: <value in [disable, enable]>
          # mms_profile: <string>
          # profile_group: <string>
          # profile_protocol_options: <string>
          # profile_type: <value in [single, group]>
          # proxy: <value in [web, ftp, wanopt]>
          # replacemsg_override_group: <string>
          # require_tfa: <value in [disable, enable]>
          # scan_botnet_connections: <value in [disable, block, monitor]>
          # schedule: <string>
          # service: <string>
          # service_negate: <value in [disable, enable]>
          # spamfilter_profile: <string>
          # srcaddr: <string>
          # srcaddr_negate: <value in [disable, enable]>
          # srcaddr6: <string>
          # ssl_ssh_profile: <string>
          # sso_auth_method: <value in [fsso, rsso, none]>
          # status: <value in [disable, enable]>
          # tags: <string>
          # transaction_based: <value in [disable, enable]>
          # transparent: <value in [disable, enable]>
          # utm_status: <value in [disable, enable]>
          # uuid: <string>
          # waf_profile: <string>
          # web_auth_cookie: <value in [disable, enable]>
          # webcache: <value in [disable, enable]>
          # webcache_https: <value in [disable, any, enable]>
          # webfilter_profile: <string>
          # webproxy_forward_server: <string>
          # webproxy_profile: <string>
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/explicit-proxy-policy'
    ]
    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_explicitproxypolicy': {
            'type': 'dict',
            'v_range': [['6.2.0', '6.2.13']],
            'options': {
                'action': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'active-auth-method': {
                    'v_range': [['6.2.0', '6.2.13']],
                    'choices': ['ntlm', 'basic', 'digest', 'form', 'none', 'negotiate'],
                    'type': 'str'
                },
                'application-list': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'av-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'casi-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'comments': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'disclaimer': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'domain', 'policy', 'user'], 'type': 'str'},
                'dlp-sensor': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'dstaddr': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'dstaddr-negate': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr6': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'dstintf': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'global-label': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'icap-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'identity-based': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'identity-based-policy': {
                    'v_range': [['6.2.0', '6.2.13']],
                    'type': 'list',
                    'options': {
                        'application-list': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'av-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'casi-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'disclaimer': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'domain', 'policy', 'user'], 'type': 'str'},
                        'dlp-sensor': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'groups': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'icap-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'id': {'v_range': [['6.2.0', '6.2.13']], 'type': 'int'},
                        'ips-sensor': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'logtraffic': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'all', 'utm'], 'type': 'str'},
                        'logtraffic-start': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mms-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'profile-group': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'profile-protocol-options': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'profile-type': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['single', 'group'], 'type': 'str'},
                        'replacemsg-override-group': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'scan-botnet-connections': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'schedule': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'spamfilter-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'ssl-ssh-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'users': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'utm-status': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'waf-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                        'webfilter-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ip-based': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-sensor': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'label': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'logtraffic': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'all', 'utm'], 'type': 'str'},
                'logtraffic-start': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'policyid': {'v_range': [['6.2.0', '6.2.13']], 'required': True, 'type': 'int'},
                'profile-group': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'profile-protocol-options': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'profile-type': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['single', 'group'], 'type': 'str'},
                'proxy': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['web', 'ftp', 'wanopt'], 'type': 'str'},
                'replacemsg-override-group': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'require-tfa': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'scan-botnet-connections': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'schedule': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'service': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'service-negate': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'spamfilter-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'srcaddr': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'srcaddr-negate': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr6': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'ssl-ssh-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'sso-auth-method': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['fsso', 'rsso', 'none'], 'type': 'str'},
                'status': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'transaction-based': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'transparent': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'utm-status': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'waf-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'web-auth-cookie': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webcache': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webcache-https': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'any', 'enable'], 'type': 'str'},
                'webfilter-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'webproxy-forward-server': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'webproxy-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_explicitproxypolicy'),
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
