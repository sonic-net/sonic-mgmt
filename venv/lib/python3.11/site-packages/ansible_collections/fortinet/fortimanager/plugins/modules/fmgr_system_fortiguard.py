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
module: fmgr_system_fortiguard
short_description: Configure FortiGuard services.
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
    system_fortiguard:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            antispam_cache:
                aliases: ['antispam-cache']
                type: str
                description: Enable/disable FortiGuard antispam request caching.
                choices:
                    - 'disable'
                    - 'enable'
            antispam_cache_mpercent:
                aliases: ['antispam-cache-mpercent']
                type: int
                description: Maximum percent of FortiGate memory the antispam cache is allowed to use
            antispam_cache_ttl:
                aliases: ['antispam-cache-ttl']
                type: int
                description: Time-to-live for antispam cache entries in seconds
            antispam_expiration:
                aliases: ['antispam-expiration']
                type: int
                description: Antispam expiration.
            antispam_force_off:
                aliases: ['antispam-force-off']
                type: str
                description: Enable/disable turning off the FortiGuard antispam service.
                choices:
                    - 'disable'
                    - 'enable'
            antispam_license:
                aliases: ['antispam-license']
                type: int
                description: Antispam license.
            antispam_timeout:
                aliases: ['antispam-timeout']
                type: int
                description: Antispam query time out
            auto_join_forticloud:
                aliases: ['auto-join-forticloud']
                type: str
                description: Automatically connect to and login to FortiCloud.
                choices:
                    - 'disable'
                    - 'enable'
            ddns_server_ip:
                aliases: ['ddns-server-ip']
                type: str
                description: IP address of the FortiDDNS server.
            ddns_server_port:
                aliases: ['ddns-server-port']
                type: int
                description: Port used to communicate with FortiDDNS servers.
            load_balance_servers:
                aliases: ['load-balance-servers']
                type: int
                description: Number of servers to alternate between as first FortiGuard option.
            outbreak_prevention_cache:
                aliases: ['outbreak-prevention-cache']
                type: str
                description: Enable/disable FortiGuard Virus Outbreak Prevention cache.
                choices:
                    - 'disable'
                    - 'enable'
            outbreak_prevention_cache_mpercent:
                aliases: ['outbreak-prevention-cache-mpercent']
                type: int
                description: Maximum percent of memory FortiGuard Virus Outbreak Prevention cache can use
            outbreak_prevention_cache_ttl:
                aliases: ['outbreak-prevention-cache-ttl']
                type: int
                description: Time-to-live for FortiGuard Virus Outbreak Prevention cache entries
            outbreak_prevention_expiration:
                aliases: ['outbreak-prevention-expiration']
                type: int
                description: Outbreak prevention expiration.
            outbreak_prevention_force_off:
                aliases: ['outbreak-prevention-force-off']
                type: str
                description: Turn off FortiGuard Virus Outbreak Prevention service.
                choices:
                    - 'disable'
                    - 'enable'
            outbreak_prevention_license:
                aliases: ['outbreak-prevention-license']
                type: int
                description: Outbreak prevention license.
            outbreak_prevention_timeout:
                aliases: ['outbreak-prevention-timeout']
                type: int
                description: FortiGuard Virus Outbreak Prevention time out
            port:
                type: str
                description: Port used to communicate with the FortiGuard servers.
                choices:
                    - '53'
                    - '80'
                    - '8888'
                    - '443'
            sdns_server_ip:
                aliases: ['sdns-server-ip']
                type: raw
                description: (list) IP address of the FortiDNS server.
            sdns_server_port:
                aliases: ['sdns-server-port']
                type: int
                description: Port used to communicate with FortiDNS servers.
            service_account_id:
                aliases: ['service-account-id']
                type: str
                description: Service account ID.
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IPv4 address used to communicate with FortiGuard.
            source_ip6:
                aliases: ['source-ip6']
                type: str
                description: Source IPv6 address used to communicate with FortiGuard.
            update_server_location:
                aliases: ['update-server-location']
                type: str
                description: Signature update server location.
                choices:
                    - 'any'
                    - 'usa'
                    - 'automatic'
                    - 'eu'
            webfilter_cache:
                aliases: ['webfilter-cache']
                type: str
                description: Enable/disable FortiGuard web filter caching.
                choices:
                    - 'disable'
                    - 'enable'
            webfilter_cache_ttl:
                aliases: ['webfilter-cache-ttl']
                type: int
                description: Time-to-live for web filter cache entries in seconds
            webfilter_expiration:
                aliases: ['webfilter-expiration']
                type: int
                description: Webfilter expiration.
            webfilter_force_off:
                aliases: ['webfilter-force-off']
                type: str
                description: Enable/disable turning off the FortiGuard web filtering service.
                choices:
                    - 'disable'
                    - 'enable'
            webfilter_license:
                aliases: ['webfilter-license']
                type: int
                description: Webfilter license.
            webfilter_timeout:
                aliases: ['webfilter-timeout']
                type: int
                description: Web filter query time out
            protocol:
                type: str
                description: Protocol used to communicate with the FortiGuard servers.
                choices:
                    - 'udp'
                    - 'http'
                    - 'https'
            proxy_password:
                aliases: ['proxy-password']
                type: raw
                description: (list) Proxy user password.
            proxy_server_ip:
                aliases: ['proxy-server-ip']
                type: str
                description: IP address of the proxy server.
            proxy_server_port:
                aliases: ['proxy-server-port']
                type: int
                description: Port used to communicate with the proxy server.
            proxy_username:
                aliases: ['proxy-username']
                type: str
                description: Proxy user name.
            sandbox_region:
                aliases: ['sandbox-region']
                type: str
                description: Cloud sandbox region.
            avquery_cache_ttl:
                aliases: ['avquery-cache-ttl']
                type: int
                description: Time-to-live for antivirus cache entries
            avquery_timeout:
                aliases: ['avquery-timeout']
                type: int
                description: Antivirus query time out
            avquery_cache:
                aliases: ['avquery-cache']
                type: str
                description: Enable/disable the FortiGuard antivirus cache.
                choices:
                    - 'disable'
                    - 'enable'
            avquery_cache_mpercent:
                aliases: ['avquery-cache-mpercent']
                type: int
                description: Maximum percent of memory the antivirus cache can use
            avquery_license:
                aliases: ['avquery-license']
                type: int
                description: Interval of time between license checks for the FortiGuard antivirus contract.
            avquery_force_off:
                aliases: ['avquery-force-off']
                type: str
                description: Turn off the FortiGuard antivirus service.
                choices:
                    - 'disable'
                    - 'enable'
            fortiguard_anycast:
                aliases: ['fortiguard-anycast']
                type: str
                description: Enable/disable use of FortiGuards anycast network.
                choices:
                    - 'disable'
                    - 'enable'
            fortiguard_anycast_source:
                aliases: ['fortiguard-anycast-source']
                type: str
                description: Configure which of Fortinets servers to provide FortiGuard services in FortiGuards anycast network.
                choices:
                    - 'fortinet'
                    - 'aws'
                    - 'debug'
            interface:
                type: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            sdns_options:
                aliases: ['sdns-options']
                type: list
                elements: str
                description: Customization options for the FortiGuard DNS service.
                choices:
                    - 'include-question-section'
            anycast_sdns_server_ip:
                aliases: ['anycast-sdns-server-ip']
                type: str
                description: IP address of the FortiGuard anycast DNS rating server.
            anycast_sdns_server_port:
                aliases: ['anycast-sdns-server-port']
                type: int
                description: Port to connect to on the FortiGuard anycast DNS rating server.
            persistent_connection:
                aliases: ['persistent-connection']
                type: str
                description: Enable/disable use of persistent connection to receive update notification from FortiGuard.
                choices:
                    - 'disable'
                    - 'enable'
            update_build_proxy:
                aliases: ['update-build-proxy']
                type: str
                description: Enable/disable proxy dictionary rebuild.
                choices:
                    - 'disable'
                    - 'enable'
            update_extdb:
                aliases: ['update-extdb']
                type: str
                description: Enable/disable external resource update.
                choices:
                    - 'disable'
                    - 'enable'
            update_ffdb:
                aliases: ['update-ffdb']
                type: str
                description: Enable/disable Internet Service Database update.
                choices:
                    - 'disable'
                    - 'enable'
            update_uwdb:
                aliases: ['update-uwdb']
                type: str
                description: Enable/disable allowlist update.
                choices:
                    - 'disable'
                    - 'enable'
            videofilter_expiration:
                aliases: ['videofilter-expiration']
                type: int
                description: Videofilter expiration.
            videofilter_license:
                aliases: ['videofilter-license']
                type: int
                description: Videofilter license.
            ddns_server_ip6:
                aliases: ['ddns-server-ip6']
                type: str
                description: IPv6 address of the FortiDDNS server.
            vdom:
                type: str
                description: FortiGuard Service virtual domain name.
            auto_firmware_upgrade:
                aliases: ['auto-firmware-upgrade']
                type: str
                description: Enable/disable automatic patch-level firmware upgrade from FortiGuard.
                choices:
                    - 'disable'
                    - 'enable'
            auto_firmware_upgrade_day:
                aliases: ['auto-firmware-upgrade-day']
                type: list
                elements: str
                description: Allowed day
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            auto_firmware_upgrade_end_hour:
                aliases: ['auto-firmware-upgrade-end-hour']
                type: int
                description: End time in the designated time window for automatic patch-level firmware upgrade from FortiGuard in 24 hour time
            auto_firmware_upgrade_start_hour:
                aliases: ['auto-firmware-upgrade-start-hour']
                type: int
                description: Start time in the designated time window for automatic patch-level firmware upgrade from FortiGuard in 24 hour time
            sandbox_inline_scan:
                aliases: ['sandbox-inline-scan']
                type: str
                description: Enable/disable FortiCloud Sandbox inline-scan.
                choices:
                    - 'disable'
                    - 'enable'
            auto_firmware_upgrade_delay:
                aliases: ['auto-firmware-upgrade-delay']
                type: int
                description: Delay of day
            gui_prompt_auto_upgrade:
                aliases: ['gui-prompt-auto-upgrade']
                type: str
                description: Enable/disable prompting of automatic patch-level firmware upgrade recommendation.
                choices:
                    - 'disable'
                    - 'enable'
            FDS_license_expiring_days:
                aliases: ['FDS-license-expiring-days']
                type: int
                description: Threshold for number of days before FortiGuard license expiration to generate license expiring event log
            antispam_cache_mpermille:
                aliases: ['antispam-cache-mpermille']
                type: int
                description: Maximum permille of FortiGate memory the antispam cache is allowed to use
            outbreak_prevention_cache_mpermille:
                aliases: ['outbreak-prevention-cache-mpermille']
                type: int
                description: Maximum permille of memory FortiGuard Virus Outbreak Prevention cache can use
            update_dldb:
                aliases: ['update-dldb']
                type: str
                description: Enable/disable DLP signature update.
                choices:
                    - 'disable'
                    - 'enable'
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
            subscribe_update_notification:
                aliases: ['subscribe-update-notification']
                type: str
                description: Enable/disable subscription to receive update notification from FortiGuard.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Configure FortiGuard services.
      fortinet.fortimanager.fmgr_system_fortiguard:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        system_fortiguard:
          # antispam_cache: <value in [disable, enable]>
          # antispam_cache_mpercent: <integer>
          # antispam_cache_ttl: <integer>
          # antispam_expiration: <integer>
          # antispam_force_off: <value in [disable, enable]>
          # antispam_license: <integer>
          # antispam_timeout: <integer>
          # auto_join_forticloud: <value in [disable, enable]>
          # ddns_server_ip: <string>
          # ddns_server_port: <integer>
          # load_balance_servers: <integer>
          # outbreak_prevention_cache: <value in [disable, enable]>
          # outbreak_prevention_cache_mpercent: <integer>
          # outbreak_prevention_cache_ttl: <integer>
          # outbreak_prevention_expiration: <integer>
          # outbreak_prevention_force_off: <value in [disable, enable]>
          # outbreak_prevention_license: <integer>
          # outbreak_prevention_timeout: <integer>
          # port: <value in [53, 80, 8888, ...]>
          # sdns_server_ip: <list or string>
          # sdns_server_port: <integer>
          # service_account_id: <string>
          # source_ip: <string>
          # source_ip6: <string>
          # update_server_location: <value in [any, usa, automatic, ...]>
          # webfilter_cache: <value in [disable, enable]>
          # webfilter_cache_ttl: <integer>
          # webfilter_expiration: <integer>
          # webfilter_force_off: <value in [disable, enable]>
          # webfilter_license: <integer>
          # webfilter_timeout: <integer>
          # protocol: <value in [udp, http, https]>
          # proxy_password: <list or string>
          # proxy_server_ip: <string>
          # proxy_server_port: <integer>
          # proxy_username: <string>
          # sandbox_region: <string>
          # avquery_cache_ttl: <integer>
          # avquery_timeout: <integer>
          # avquery_cache: <value in [disable, enable]>
          # avquery_cache_mpercent: <integer>
          # avquery_license: <integer>
          # avquery_force_off: <value in [disable, enable]>
          # fortiguard_anycast: <value in [disable, enable]>
          # fortiguard_anycast_source: <value in [fortinet, aws, debug]>
          # interface: <string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # sdns_options:
          #   - "include-question-section"
          # anycast_sdns_server_ip: <string>
          # anycast_sdns_server_port: <integer>
          # persistent_connection: <value in [disable, enable]>
          # update_build_proxy: <value in [disable, enable]>
          # update_extdb: <value in [disable, enable]>
          # update_ffdb: <value in [disable, enable]>
          # update_uwdb: <value in [disable, enable]>
          # videofilter_expiration: <integer>
          # videofilter_license: <integer>
          # ddns_server_ip6: <string>
          # vdom: <string>
          # auto_firmware_upgrade: <value in [disable, enable]>
          # auto_firmware_upgrade_day:
          #   - "sunday"
          #   - "monday"
          #   - "tuesday"
          #   - "wednesday"
          #   - "thursday"
          #   - "friday"
          #   - "saturday"
          # auto_firmware_upgrade_end_hour: <integer>
          # auto_firmware_upgrade_start_hour: <integer>
          # sandbox_inline_scan: <value in [disable, enable]>
          # auto_firmware_upgrade_delay: <integer>
          # gui_prompt_auto_upgrade: <value in [disable, enable]>
          # FDS_license_expiring_days: <integer>
          # antispam_cache_mpermille: <integer>
          # outbreak_prevention_cache_mpermille: <integer>
          # update_dldb: <value in [disable, enable]>
          # vrf_select: <integer>
          # subscribe_update_notification: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/system/fortiguard',
        '/pm/config/global/obj/system/fortiguard'
    ]
    url_params = ['adom']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_fortiguard': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'antispam-cache': {'choices': ['disable', 'enable'], 'type': 'str'},
                'antispam-cache-mpercent': {'type': 'int'},
                'antispam-cache-ttl': {'type': 'int'},
                'antispam-expiration': {'type': 'int'},
                'antispam-force-off': {'choices': ['disable', 'enable'], 'type': 'str'},
                'antispam-license': {'type': 'int'},
                'antispam-timeout': {'type': 'int'},
                'auto-join-forticloud': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ddns-server-ip': {'type': 'str'},
                'ddns-server-port': {'type': 'int'},
                'load-balance-servers': {'type': 'int'},
                'outbreak-prevention-cache': {'choices': ['disable', 'enable'], 'type': 'str'},
                'outbreak-prevention-cache-mpercent': {'type': 'int'},
                'outbreak-prevention-cache-ttl': {'type': 'int'},
                'outbreak-prevention-expiration': {'type': 'int'},
                'outbreak-prevention-force-off': {'choices': ['disable', 'enable'], 'type': 'str'},
                'outbreak-prevention-license': {'type': 'int'},
                'outbreak-prevention-timeout': {'type': 'int'},
                'port': {'choices': ['53', '80', '8888', '443'], 'type': 'str'},
                'sdns-server-ip': {'type': 'raw'},
                'sdns-server-port': {'type': 'int'},
                'service-account-id': {'type': 'str'},
                'source-ip': {'type': 'str'},
                'source-ip6': {'type': 'str'},
                'update-server-location': {'choices': ['any', 'usa', 'automatic', 'eu'], 'type': 'str'},
                'webfilter-cache': {'choices': ['disable', 'enable'], 'type': 'str'},
                'webfilter-cache-ttl': {'type': 'int'},
                'webfilter-expiration': {'type': 'int'},
                'webfilter-force-off': {'choices': ['disable', 'enable'], 'type': 'str'},
                'webfilter-license': {'type': 'int'},
                'webfilter-timeout': {'type': 'int'},
                'protocol': {'v_range': [['6.2.0', '']], 'choices': ['udp', 'http', 'https'], 'type': 'str'},
                'proxy-password': {'v_range': [['6.2.1', '']], 'no_log': True, 'type': 'raw'},
                'proxy-server-ip': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'proxy-server-port': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'proxy-username': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'sandbox-region': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'avquery-cache-ttl': {'v_range': [['6.2.0', '6.4.15']], 'type': 'int'},
                'avquery-timeout': {'v_range': [['6.2.0', '6.4.15']], 'type': 'int'},
                'avquery-cache': {'v_range': [['6.2.0', '6.4.15']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'avquery-cache-mpercent': {'v_range': [['6.2.0', '6.4.15']], 'type': 'int'},
                'avquery-license': {'v_range': [['6.2.0', '6.4.15']], 'type': 'int'},
                'avquery-force-off': {'v_range': [['6.2.0', '6.4.15']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiguard-anycast': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiguard-anycast-source': {'v_range': [['6.2.2', '']], 'choices': ['fortinet', 'aws', 'debug'], 'type': 'str'},
                'interface': {'v_range': [['6.2.5', '6.2.13'], ['6.4.1', '']], 'type': 'str'},
                'interface-select-method': {'v_range': [['6.2.5', '6.2.13'], ['6.4.1', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'sdns-options': {'v_range': [['6.4.0', '']], 'type': 'list', 'choices': ['include-question-section'], 'elements': 'str'},
                'anycast-sdns-server-ip': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'anycast-sdns-server-port': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'persistent-connection': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-build-proxy': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-extdb': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-ffdb': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-uwdb': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'videofilter-expiration': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'videofilter-license': {'v_range': [['7.0.0', '']], 'type': 'int'},
                'ddns-server-ip6': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'vdom': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'auto-firmware-upgrade': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-firmware-upgrade-day': {
                    'v_range': [['7.2.1', '']],
                    'type': 'list',
                    'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'],
                    'elements': 'str'
                },
                'auto-firmware-upgrade-end-hour': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'auto-firmware-upgrade-start-hour': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'sandbox-inline-scan': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-firmware-upgrade-delay': {'v_range': [['7.2.4', '']], 'type': 'int'},
                'gui-prompt-auto-upgrade': {'v_range': [['7.2.4', '7.2.11'], ['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'FDS-license-expiring-days': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'antispam-cache-mpermille': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'outbreak-prevention-cache-mpermille': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'update-dldb': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'subscribe-update-notification': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_fortiguard'),
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
