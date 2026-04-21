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
module: fmgr_system_admin_user
short_description: Admin user.
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
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    system_admin_user:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            adom:
                type: list
                elements: dict
                description: Adom.
                suboptions:
                    adom_name:
                        aliases: ['adom-name']
                        type: str
                        description: Admin domain names.
            adom_exclude:
                aliases: ['adom-exclude']
                type: list
                elements: dict
                description: Adom exclude.
                suboptions:
                    adom_name:
                        aliases: ['adom-name']
                        type: str
                        description: Admin domain names.
            app_filter:
                aliases: ['app-filter']
                type: list
                elements: dict
                description: App filter.
                suboptions:
                    app_filter_name:
                        aliases: ['app-filter-name']
                        type: str
                        description: App filter name.
            avatar:
                type: str
                description: Image file for avatar
            ca:
                type: str
                description: PKI user certificate CA
            change_password:
                aliases: ['change-password']
                type: str
                description:
                    - Enable/disable restricted user to change self password.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            dashboard:
                type: list
                elements: dict
                description: Dashboard.
                suboptions:
                    column:
                        type: int
                        description: Widgets column ID.
                    diskio_content_type:
                        aliases: ['diskio-content-type']
                        type: str
                        description:
                            - Disk I/O Monitor widgets chart type.
                            - util - bandwidth utilization.
                            - iops - the number of I/O requests.
                            - blks - the amount of data of I/O requests.
                        choices:
                            - 'util'
                            - 'iops'
                            - 'blks'
                    diskio_period:
                        aliases: ['diskio-period']
                        type: str
                        description:
                            - Disk I/O Monitor widgets data period.
                            - 1hour - 1 hour.
                            - 8hour - 8 hour.
                            - 24hour - 24 hour.
                        choices:
                            - '1hour'
                            - '8hour'
                            - '24hour'
                    log_rate_period:
                        aliases: ['log-rate-period']
                        type: str
                        description:
                            - Log receive monitor widgets data period.
                            - 2min  - 2 minutes.
                            - 1hour - 1 hour.
                            - 6hours - 6 hours.
                        choices:
                            - '2min'
                            - '1hour'
                            - '6hours'
                    log_rate_topn:
                        aliases: ['log-rate-topn']
                        type: str
                        description:
                            - Log receive monitor widgets number of top items to display.
                            - 1 - Top 1.
                            - 2 - Top 2.
                            - 3 - Top 3.
                            - 4 - Top 4.
                            - 5 - Top 5.
                        choices:
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                    log_rate_type:
                        aliases: ['log-rate-type']
                        type: str
                        description:
                            - Log receive monitor widgets statistics breakdown options.
                            - log - Show log rates for each log type.
                            - device - Show log rates for each device.
                        choices:
                            - 'log'
                            - 'device'
                    moduleid:
                        type: int
                        description: Widget ID.
                    name:
                        type: str
                        description: Widget name.
                    num_entries:
                        aliases: ['num-entries']
                        type: int
                        description: Number of entries.
                    refresh_interval:
                        aliases: ['refresh-interval']
                        type: int
                        description: Widgets refresh interval.
                    res_cpu_display:
                        aliases: ['res-cpu-display']
                        type: str
                        description:
                            - Widgets CPU display type.
                            - average  - Average usage of CPU.
                            - each - Each usage of CPU.
                        choices:
                            - 'average'
                            - 'each'
                    res_period:
                        aliases: ['res-period']
                        type: str
                        description:
                            - Widgets data period.
                            - 10min  - Last 10 minutes.
                            - hour - Last hour.
                            - day - Last day.
                        choices:
                            - '10min'
                            - 'hour'
                            - 'day'
                    res_view_type:
                        aliases: ['res-view-type']
                        type: str
                        description:
                            - Widgets data view type.
                            - real-time  - Real-time view.
                            - history - History view.
                        choices:
                            - 'real-time'
                            - 'history'
                    status:
                        type: str
                        description:
                            - Widgets opened/closed state.
                            - close - Widget closed.
                            - open - Widget opened.
                        choices:
                            - 'close'
                            - 'open'
                    tabid:
                        type: int
                        description: ID of tab where widget is displayed.
                    time_period:
                        aliases: ['time-period']
                        type: str
                        description:
                            - Log Database Monitor widgets data period.
                            - 1hour - 1 hour.
                            - 8hour - 8 hour.
                            - 24hour - 24 hour.
                        choices:
                            - '1hour'
                            - '8hour'
                            - '24hour'
                    widget_type:
                        aliases: ['widget-type']
                        type: str
                        description:
                            - Widget type.
                            - top-lograte - Log Receive Monitor.
                            - sysres - System resources.
                            - sysinfo - System Information.
                            - licinfo - License Information.
                            - jsconsole - CLI Console.
                            - sysop - Unit Operation.
                            - alert - Alert Message Console.
                            - statistics - Statistics.
                            - rpteng - Report Engine.
                            - raid - Disk Monitor.
                            - logrecv - Logs/Data Received.
                            - devsummary - Device Summary.
                            - logdb-perf - Log Database Performance Monitor.
                            - logdb-lag - Log Database Lag Time.
                            - disk-io - Disk I/O.
                            - log-rcvd-fwd - Log receive and forwarding Monitor.
                        choices:
                            - 'top-lograte'
                            - 'sysres'
                            - 'sysinfo'
                            - 'licinfo'
                            - 'jsconsole'
                            - 'sysop'
                            - 'alert'
                            - 'statistics'
                            - 'rpteng'
                            - 'raid'
                            - 'logrecv'
                            - 'devsummary'
                            - 'logdb-perf'
                            - 'logdb-lag'
                            - 'disk-io'
                            - 'log-rcvd-fwd'
            dashboard_tabs:
                aliases: ['dashboard-tabs']
                type: list
                elements: dict
                description: Dashboard tabs.
                suboptions:
                    name:
                        type: str
                        description: Tab name.
                    tabid:
                        type: int
                        description: Tab ID.
            description:
                type: str
                description: Description.
            dev_group:
                aliases: ['dev-group']
                type: str
                description: Device group.
            email_address:
                aliases: ['email-address']
                type: str
                description: Email address.
            ext_auth_accprofile_override:
                aliases: ['ext-auth-accprofile-override']
                type: str
                description:
                    - Allow to use the access profile provided by the remote authentication server.
                    - disable - Disable access profile override.
                    - enable - Enable access profile override.
                choices:
                    - 'disable'
                    - 'enable'
            ext_auth_adom_override:
                aliases: ['ext-auth-adom-override']
                type: str
                description:
                    - Allow to use the ADOM provided by the remote authentication server.
                    - disable - Disable ADOM override.
                    - enable - Enable ADOM override.
                choices:
                    - 'disable'
                    - 'enable'
            ext_auth_group_match:
                aliases: ['ext-auth-group-match']
                type: str
                description: Only administrators belonging to this group can login.
            first_name:
                aliases: ['first-name']
                type: str
                description: First name.
            force_password_change:
                aliases: ['force-password-change']
                type: str
                description:
                    - Enable/disable force password change on next login.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            group:
                type: str
                description: Group name.
            hidden:
                type: int
                description: Hidden administrator.
            ips_filter:
                aliases: ['ips-filter']
                type: list
                elements: dict
                description: Ips filter.
                suboptions:
                    ips_filter_name:
                        aliases: ['ips-filter-name']
                        type: str
                        description: IPS filter name.
            ipv6_trusthost1:
                type: str
                description: Admin user trusted host IPv6, default
            ipv6_trusthost10:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost2:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost3:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost4:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost5:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost6:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost7:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost8:
                type: str
                description: Admin user trusted host IPv6, default ffff
            ipv6_trusthost9:
                type: str
                description: Admin user trusted host IPv6, default ffff
            last_name:
                aliases: ['last-name']
                type: str
                description: Last name.
            ldap_server:
                aliases: ['ldap-server']
                type: str
                description: LDAP server name.
            meta_data:
                aliases: ['meta-data']
                type: list
                elements: dict
                description: Meta data.
                suboptions:
                    fieldlength:
                        type: int
                        description: Field length.
                    fieldname:
                        type: str
                        description: Field name.
                    fieldvalue:
                        type: str
                        description: Field value.
                    importance:
                        type: str
                        description:
                            - Importance.
                            - optional - This field is optional.
                            - required - This field is required.
                        choices:
                            - 'optional'
                            - 'required'
                    status:
                        type: str
                        description:
                            - Status.
                            - disabled - This field is disabled.
                            - enabled - This field is enabled.
                        choices:
                            - 'disabled'
                            - 'enabled'
            mobile_number:
                aliases: ['mobile-number']
                type: str
                description: Mobile number.
            pager_number:
                aliases: ['pager-number']
                type: str
                description: Pager number.
            password:
                type: raw
                description: (list) Password.
            password_expire:
                aliases: ['password-expire']
                type: raw
                description: (list or str) Password expire time in GMT.
            phone_number:
                aliases: ['phone-number']
                type: str
                description: Phone number.
            policy_package:
                aliases: ['policy-package']
                type: list
                elements: dict
                description: Policy package.
                suboptions:
                    policy_package_name:
                        aliases: ['policy-package-name']
                        type: str
                        description: Policy package names.
            profileid:
                type: str
                description: Profile ID.
            radius_server:
                type: str
                description: RADIUS server name.
            restrict_access:
                aliases: ['restrict-access']
                type: str
                description:
                    - Enable/disable restricted access to development VDOM.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            restrict_dev_vdom:
                aliases: ['restrict-dev-vdom']
                type: list
                elements: dict
                description: Restrict dev vdom.
                suboptions:
                    dev_vdom:
                        aliases: ['dev-vdom']
                        type: str
                        description: Device or device VDOM.
            rpc_permit:
                aliases: ['rpc-permit']
                type: str
                description:
                    - set none/read/read-write rpc-permission.
                    - read-write - Read-write permission.
                    - none - No permission.
                    - read - Read-only permission.
                choices:
                    - 'read-write'
                    - 'none'
                    - 'read'
                    - 'from-profile'
            ssh_public_key1:
                aliases: ['ssh-public-key1']
                type: raw
                description: (list) SSH public key 1.
            ssh_public_key2:
                aliases: ['ssh-public-key2']
                type: raw
                description: (list) SSH public key 2.
            ssh_public_key3:
                aliases: ['ssh-public-key3']
                type: raw
                description: (list) SSH public key 3.
            subject:
                type: str
                description: PKI user certificate name constraints.
            tacacs_plus_server:
                aliases: ['tacacs-plus-server']
                type: str
                description: TACACS+ server name.
            trusthost1:
                type: str
                description: Admin user trusted host IP, default 0.
            trusthost10:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost2:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost3:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost4:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost5:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost6:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost7:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost8:
                type: str
                description: Admin user trusted host IP, default 255.
            trusthost9:
                type: str
                description: Admin user trusted host IP, default 255.
            two_factor_auth:
                aliases: ['two-factor-auth']
                type: str
                description:
                    - Enable 2-factor authentication
                    - disable - Disable 2-factor authentication.
                    - enable - Enable 2-factor authentication.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'password'
                    - 'ftc-ftm'
                    - 'ftc-email'
                    - 'ftc-sms'
            user_type:
                type: str
                description:
                    - User type.
                    - local - Local user.
                    - radius - RADIUS user.
                    - ldap - LDAP user.
                    - tacacs-plus - TACACS+ user.
                    - pki-auth - PKI user.
                    - group - Group user.
                choices:
                    - 'local'
                    - 'radius'
                    - 'ldap'
                    - 'tacacs-plus'
                    - 'pki-auth'
                    - 'group'
                    - 'sso'
                    - 'api'
            userid:
                type: str
                description: User name.
                required: true
            web_filter:
                aliases: ['web-filter']
                type: list
                elements: dict
                description: Web filter.
                suboptions:
                    web_filter_name:
                        aliases: ['web-filter-name']
                        type: str
                        description: Web filter name.
            wildcard:
                type: str
                description:
                    - Enable/disable wildcard remote authentication.
                    - disable - Disable username wildcard.
                    - enable - Enable username wildcard.
                choices:
                    - 'disable'
                    - 'enable'
            login_max:
                aliases: ['login-max']
                type: int
                description: Max login session for this user.
            use_global_theme:
                aliases: ['use-global-theme']
                type: str
                description:
                    - Enable/disble global theme for administration GUI.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            user_theme:
                aliases: ['user-theme']
                type: str
                description:
                    - Color scheme to use for the admin user GUI.
                    - blue - Blueberry
                    - green - Kiwi
                    - red - Cherry
                    - melongene - Plum
                    - spring - Spring
                    - summer - Summer
                    - autumn - Autumn
                    - winter - Winter
                    - circuit-board - Circuit Board
                    - calla-lily - Calla Lily
                    - binary-tunnel - Binary Tunnel
                    - mars - Mars
                    - blue-sea - Blue Sea
                    - technology - Technology
                    - landscape - Landscape
                    - twilight - Twilight
                    - canyon - Canyon
                    - northern-light - Northern Light
                    - astronomy - Astronomy
                    - fish - Fish
                    - penguin - Penguin
                    - mountain - Mountain
                    - panda - Panda
                    - parrot - Parrot
                    - cave - Cave
                    - zebra - Zebra
                    - contrast-dark - High Contrast Dark
                choices:
                    - 'blue'
                    - 'green'
                    - 'red'
                    - 'melongene'
                    - 'spring'
                    - 'summer'
                    - 'autumn'
                    - 'winter'
                    - 'circuit-board'
                    - 'calla-lily'
                    - 'binary-tunnel'
                    - 'mars'
                    - 'blue-sea'
                    - 'technology'
                    - 'landscape'
                    - 'twilight'
                    - 'canyon'
                    - 'northern-light'
                    - 'astronomy'
                    - 'fish'
                    - 'penguin'
                    - 'mountain'
                    - 'panda'
                    - 'parrot'
                    - 'cave'
                    - 'zebra'
                    - 'contrast-dark'
                    - 'mariner'
                    - 'jade'
                    - 'neutrino'
                    - 'dark-matter'
                    - 'forest'
                    - 'cat'
                    - 'graphite'
            adom_access:
                aliases: ['adom-access']
                type: str
                description:
                    - set all/specify/exclude adom access mode.
                    - all - All ADOMs access.
                    - specify - Specify ADOMs access.
                    - exclude - Exclude ADOMs access.
                choices:
                    - 'all'
                    - 'specify'
                    - 'exclude'
                    - 'per-adom-profile'
            fingerprint:
                type: str
                description: PKI user certificate fingerprint
            th_from_profile:
                aliases: ['th-from-profile']
                type: int
                description: Internal use only
            th6_from_profile:
                aliases: ['th6-from-profile']
                type: int
                description: Internal use only
            cors_allow_origin:
                aliases: ['cors-allow-origin']
                type: str
                description: Access-Control-Allow-Origin.
            fortiai:
                type: str
                description:
                    - Enable/disble FortiAI.
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices:
                    - 'disable'
                    - 'enable'
            policy_block:
                aliases: ['policy-block']
                type: list
                elements: dict
                description: Policy block.
                suboptions:
                    policy_block_name:
                        aliases: ['policy-block-name']
                        type: str
                        description: Policy block names.
            old_password:
                aliases: ['old-password']
                type: str
                description: Old password.
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Admin User
      fortinet.fortimanager.fmgr_system_admin_user:
        state: present
        system_admin_user:
          adom:
            - adom_name: ansible
          userid: "ansible-test"
    - name: Admin domain.
      fortinet.fortimanager.fmgr_system_admin_user_adom:
        bypass_validation: false
        user: ansible-test # userid
        state: present
        system_admin_user_adom:
          adom_name: "ALL ADOMS"
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
        '/cli/global/system/admin/user'
    ]
    url_params = []
    module_primary_key = 'userid'
    module_arg_spec = {
        'system_admin_user': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'adom': {'type': 'list', 'options': {'adom-name': {'type': 'str'}}, 'elements': 'dict'},
                'adom-exclude': {
                    'v_range': [['6.0.0', '7.0.2']],
                    'type': 'list',
                    'options': {'adom-name': {'v_range': [['6.0.0', '7.0.2']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'app-filter': {'type': 'list', 'options': {'app-filter-name': {'type': 'str'}}, 'elements': 'dict'},
                'avatar': {'type': 'str'},
                'ca': {'type': 'str'},
                'change-password': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dashboard': {
                    'type': 'list',
                    'options': {
                        'column': {'type': 'int'},
                        'diskio-content-type': {'choices': ['util', 'iops', 'blks'], 'type': 'str'},
                        'diskio-period': {'choices': ['1hour', '8hour', '24hour'], 'type': 'str'},
                        'log-rate-period': {'choices': ['2min', '1hour', '6hours'], 'type': 'str'},
                        'log-rate-topn': {'choices': ['1', '2', '3', '4', '5'], 'type': 'str'},
                        'log-rate-type': {'choices': ['log', 'device'], 'type': 'str'},
                        'moduleid': {'type': 'int'},
                        'name': {'type': 'str'},
                        'num-entries': {'type': 'int'},
                        'refresh-interval': {'type': 'int'},
                        'res-cpu-display': {'choices': ['average', 'each'], 'type': 'str'},
                        'res-period': {'choices': ['10min', 'hour', 'day'], 'type': 'str'},
                        'res-view-type': {'choices': ['real-time', 'history'], 'type': 'str'},
                        'status': {'choices': ['close', 'open'], 'type': 'str'},
                        'tabid': {'type': 'int'},
                        'time-period': {'choices': ['1hour', '8hour', '24hour'], 'type': 'str'},
                        'widget-type': {
                            'choices': [
                                'top-lograte', 'sysres', 'sysinfo', 'licinfo', 'jsconsole', 'sysop', 'alert', 'statistics', 'rpteng', 'raid', 'logrecv',
                                'devsummary', 'logdb-perf', 'logdb-lag', 'disk-io', 'log-rcvd-fwd'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'dashboard-tabs': {'type': 'list', 'options': {'name': {'type': 'str'}, 'tabid': {'type': 'int'}}, 'elements': 'dict'},
                'description': {'type': 'str'},
                'dev-group': {'type': 'str'},
                'email-address': {'type': 'str'},
                'ext-auth-accprofile-override': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ext-auth-adom-override': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ext-auth-group-match': {'type': 'str'},
                'first-name': {'type': 'str'},
                'force-password-change': {'choices': ['disable', 'enable'], 'type': 'str'},
                'group': {'type': 'str'},
                'hidden': {'type': 'int'},
                'ips-filter': {'type': 'list', 'options': {'ips-filter-name': {'type': 'str'}}, 'elements': 'dict'},
                'ipv6_trusthost1': {'type': 'str'},
                'ipv6_trusthost10': {'type': 'str'},
                'ipv6_trusthost2': {'type': 'str'},
                'ipv6_trusthost3': {'type': 'str'},
                'ipv6_trusthost4': {'type': 'str'},
                'ipv6_trusthost5': {'type': 'str'},
                'ipv6_trusthost6': {'type': 'str'},
                'ipv6_trusthost7': {'type': 'str'},
                'ipv6_trusthost8': {'type': 'str'},
                'ipv6_trusthost9': {'type': 'str'},
                'last-name': {'type': 'str'},
                'ldap-server': {'type': 'str'},
                'meta-data': {
                    'type': 'list',
                    'options': {
                        'fieldlength': {'type': 'int'},
                        'fieldname': {'type': 'str'},
                        'fieldvalue': {'type': 'str'},
                        'importance': {'choices': ['optional', 'required'], 'type': 'str'},
                        'status': {'choices': ['disabled', 'enabled'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mobile-number': {'type': 'str'},
                'pager-number': {'type': 'str'},
                'password': {'no_log': True, 'type': 'raw'},
                'password-expire': {'no_log': True, 'type': 'raw'},
                'phone-number': {'type': 'str'},
                'policy-package': {'type': 'list', 'options': {'policy-package-name': {'type': 'str'}}, 'elements': 'dict'},
                'profileid': {'type': 'str'},
                'radius_server': {'type': 'str'},
                'restrict-access': {'v_range': [['6.0.0', '6.2.3'], ['6.4.0', '6.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'restrict-dev-vdom': {
                    'v_range': [['6.0.0', '6.2.3'], ['6.4.0', '6.4.0']],
                    'type': 'list',
                    'options': {'dev-vdom': {'v_range': [['6.0.0', '6.2.3'], ['6.4.0', '6.4.0']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'rpc-permit': {'choices': ['read-write', 'none', 'read', 'from-profile'], 'type': 'str'},
                'ssh-public-key1': {'no_log': True, 'type': 'raw'},
                'ssh-public-key2': {'no_log': True, 'type': 'raw'},
                'ssh-public-key3': {'no_log': True, 'type': 'raw'},
                'subject': {'type': 'str'},
                'tacacs-plus-server': {'type': 'str'},
                'trusthost1': {'type': 'str'},
                'trusthost10': {'type': 'str'},
                'trusthost2': {'type': 'str'},
                'trusthost3': {'type': 'str'},
                'trusthost4': {'type': 'str'},
                'trusthost5': {'type': 'str'},
                'trusthost6': {'type': 'str'},
                'trusthost7': {'type': 'str'},
                'trusthost8': {'type': 'str'},
                'trusthost9': {'type': 'str'},
                'two-factor-auth': {'choices': ['disable', 'enable', 'password', 'ftc-ftm', 'ftc-email', 'ftc-sms'], 'type': 'str'},
                'user_type': {'choices': ['local', 'radius', 'ldap', 'tacacs-plus', 'pki-auth', 'group', 'sso', 'api'], 'type': 'str'},
                'userid': {'required': True, 'type': 'str'},
                'web-filter': {'type': 'list', 'options': {'web-filter-name': {'type': 'str'}}, 'elements': 'dict'},
                'wildcard': {'choices': ['disable', 'enable'], 'type': 'str'},
                'login-max': {'v_range': [['6.4.6', '']], 'type': 'int'},
                'use-global-theme': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user-theme': {
                    'v_range': [['7.0.0', '']],
                    'choices': [
                        'blue', 'green', 'red', 'melongene', 'spring', 'summer', 'autumn', 'winter', 'circuit-board', 'calla-lily', 'binary-tunnel',
                        'mars', 'blue-sea', 'technology', 'landscape', 'twilight', 'canyon', 'northern-light', 'astronomy', 'fish', 'penguin',
                        'mountain', 'panda', 'parrot', 'cave', 'zebra', 'contrast-dark', 'mariner', 'jade', 'neutrino', 'dark-matter', 'forest', 'cat',
                        'graphite'
                    ],
                    'type': 'str'
                },
                'adom-access': {'v_range': [['7.0.3', '']], 'choices': ['all', 'specify', 'exclude', 'per-adom-profile'], 'type': 'str'},
                'fingerprint': {'v_range': [['6.4.8', '6.4.15'], ['7.0.4', '']], 'type': 'str'},
                'th-from-profile': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'th6-from-profile': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'cors-allow-origin': {'v_range': [['7.2.2', '']], 'type': 'str'},
                'fortiai': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'policy-block': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'options': {'policy-block-name': {'v_range': [['7.6.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'old-password': {'v_range': [['7.2.11', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']], 'no_log': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin_user'),
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
