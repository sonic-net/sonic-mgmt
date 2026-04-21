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
module: fmgr_fmupdate_webspam_fgdsetting
short_description: Configure the FortiGuard run parameters.
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
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    fmupdate_webspam_fgdsetting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            as_cache:
                aliases: ['as-cache']
                type: int
                description: Antispam service maximum memory usage in megabytes
            as_log:
                aliases: ['as-log']
                type: str
                description:
                    - Antispam log setting
                    - disable - Disable spam log.
                    - nospam - Log non-spam events.
                    - all - Log all spam lookups.
                choices:
                    - 'disable'
                    - 'nospam'
                    - 'all'
            as_preload:
                aliases: ['as-preload']
                type: str
                description:
                    - Enable/disable preloading antispam database to memory
                    - disable - Disable antispam database preload.
                    - enable - Enable antispam database preload.
                choices:
                    - 'disable'
                    - 'enable'
            av_cache:
                aliases: ['av-cache']
                type: int
                description: Antivirus service maximum memory usage, in megabytes
            av_log:
                aliases: ['av-log']
                type: str
                description:
                    - Antivirus log setting
                    - disable - Disable virus log.
                    - novirus - Log non-virus events.
                    - all - Log all virus lookups.
                choices:
                    - 'disable'
                    - 'novirus'
                    - 'all'
            av_preload:
                aliases: ['av-preload']
                type: str
                description:
                    - Enable/disable preloading antivirus database to memory
                    - disable - Disable antivirus database preload.
                    - enable - Enable antivirus database preload.
                choices:
                    - 'disable'
                    - 'enable'
            av2_cache:
                aliases: ['av2-cache']
                type: int
                description: Antispam service maximum memory usage in megabytes
            av2_log:
                aliases: ['av2-log']
                type: str
                description:
                    - Outbreak prevention log setting
                    - disable - Disable av2 log.
                    - noav2 - Log non-av2 events.
                    - all - Log all av2 lookups.
                choices:
                    - 'disable'
                    - 'noav2'
                    - 'all'
            av2_preload:
                aliases: ['av2-preload']
                type: str
                description:
                    - Enable/disable preloading outbreak prevention database to memory
                    - disable - Disable outbreak prevention database preload.
                    - enable - Enable outbreak prevention database preload.
                choices:
                    - 'disable'
                    - 'enable'
            eventlog_query:
                aliases: ['eventlog-query']
                type: str
                description:
                    - Enable/disable record query to event-log besides fgd-log
                    - disable - Record query to event-log besides fgd-log.
                    - enable - Do not log to event-log.
                choices:
                    - 'disable'
                    - 'enable'
            fgd_pull_interval:
                aliases: ['fgd-pull-interval']
                type: int
                description: Fgd pull interval setting, in minutes
            fq_cache:
                aliases: ['fq-cache']
                type: int
                description: File query service maximum memory usage, in megabytes
            fq_log:
                aliases: ['fq-log']
                type: str
                description:
                    - File query log setting
                    - disable - Disable file query log.
                    - nofilequery - Log non-file query events.
                    - all - Log all file query events.
                choices:
                    - 'disable'
                    - 'nofilequery'
                    - 'all'
            fq_preload:
                aliases: ['fq-preload']
                type: str
                description:
                    - Enable/disable preloading file query database to memory
                    - disable - Disable file query db preload.
                    - enable - Enable file query db preload.
                choices:
                    - 'disable'
                    - 'enable'
            linkd_log:
                aliases: ['linkd-log']
                type: str
                description:
                    - Linkd log setting
                    - emergency - The unit is unusable.
                    - alert - Immediate action is required
                    - critical - Functionality is affected.
                    - error - Functionality is probably affected.
                    - warn - Functionality might be affected.
                    - notice - Information about normal events.
                    - info - General information.
                    - debug - Debug information.
                    - disable - Linkd logging is disabled.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warn'
                    - 'notice'
                    - 'info'
                    - 'debug'
                    - 'disable'
            max_client_worker:
                aliases: ['max-client-worker']
                type: int
                description: Max worker for tcp client connection
            max_log_quota:
                aliases: ['max-log-quota']
                type: int
                description: Maximum log quota setting, in megabytes
            max_unrated_site:
                aliases: ['max-unrated-site']
                type: int
                description: Maximum number of unrated site in memory, in kilobytes
            restrict_as1_dbver:
                aliases: ['restrict-as1-dbver']
                type: str
                description: Restrict system update to indicated antispam
            restrict_as2_dbver:
                aliases: ['restrict-as2-dbver']
                type: str
                description: Restrict system update to indicated antispam
            restrict_as4_dbver:
                aliases: ['restrict-as4-dbver']
                type: str
                description: Restrict system update to indicated antispam
            restrict_av_dbver:
                aliases: ['restrict-av-dbver']
                type: str
                description: Restrict system update to indicated antivirus database version
            restrict_av2_dbver:
                aliases: ['restrict-av2-dbver']
                type: str
                description: Restrict system update to indicated outbreak prevention database version
            restrict_fq_dbver:
                aliases: ['restrict-fq-dbver']
                type: str
                description: Restrict system update to indicated file query database version
            restrict_wf_dbver:
                aliases: ['restrict-wf-dbver']
                type: str
                description: Restrict system update to indicated web filter database version
            server_override:
                aliases: ['server-override']
                type: dict
                description: Server override.
                suboptions:
                    servlist:
                        type: list
                        elements: dict
                        description: Servlist.
                        suboptions:
                            id:
                                type: int
                                description: Override server ID
                            ip:
                                type: str
                                description: IPv4 address of the override server.
                            ip6:
                                type: str
                                description: IPv6 address of the override server.
                            port:
                                type: int
                                description: Port number to use when contacting FortiGuard
                            service_type:
                                aliases: ['service-type']
                                type: raw
                                description:
                                    - (list or str)
                                    - Override service type.
                                    - fgd - Server override config for fgd
                                    - fgc - Server override config for fgc
                                    - fsa - Server override config for fsa
                                choices:
                                    - 'fgd'
                                    - 'fgc'
                                    - 'fsa'
                                    - 'fgfq'
                                    - 'geoip'
                                    - 'iot-collect'
                    status:
                        type: str
                        description:
                            - Override status.
                            - disable - Disable setting.
                            - enable - Enable setting.
                        choices:
                            - 'disable'
                            - 'enable'
            stat_log_interval:
                aliases: ['stat-log-interval']
                type: int
                description: Statistic log interval setting, in minutes
            stat_sync_interval:
                aliases: ['stat-sync-interval']
                type: int
                description: Synchronization interval for statistic of unrated site in minutes
            update_interval:
                aliases: ['update-interval']
                type: int
                description: FortiGuard database update wait time if not enough delta files, in hours
            update_log:
                aliases: ['update-log']
                type: str
                description:
                    - Enable/disable update log setting
                    - disable - Disable update log.
                    - enable - Enable update log.
                choices:
                    - 'disable'
                    - 'enable'
            wf_cache:
                aliases: ['wf-cache']
                type: int
                description: Web filter service maximum memory usage, in megabytes
            wf_dn_cache_expire_time:
                aliases: ['wf-dn-cache-expire-time']
                type: int
                description: Web filter DN cache expire time, in minutes
            wf_dn_cache_max_number:
                aliases: ['wf-dn-cache-max-number']
                type: int
                description: Maximum number of Web filter DN cache
            wf_log:
                aliases: ['wf-log']
                type: str
                description:
                    - Web filter log setting
                    - disable - Disable URL log.
                    - nourl - Log non-URL events.
                    - all - Log all URL lookups.
                choices:
                    - 'disable'
                    - 'nourl'
                    - 'all'
            wf_preload:
                aliases: ['wf-preload']
                type: str
                description:
                    - Enable/disable preloading the web filter database into memory
                    - disable - Disable web filter database preload.
                    - enable - Enable web filter database preload.
                choices:
                    - 'disable'
                    - 'enable'
            iot_cache:
                aliases: ['iot-cache']
                type: int
                description: IoT service maximum memory usage, in megabytes
            iot_log:
                aliases: ['iot-log']
                type: str
                description:
                    - IoT log setting
                    - disable - Disable IoT log.
                    - nofilequery - Log non-IoT events.
                    - all - Log all IoT events.
                choices:
                    - 'disable'
                    - 'nofilequery'
                    - 'all'
                    - 'noiot'
            iot_preload:
                aliases: ['iot-preload']
                type: str
                description:
                    - Enable/disable preloading IoT database to memory
                    - disable - Disable IoT db preload.
                    - enable - Enable IoT db preload.
                choices:
                    - 'disable'
                    - 'enable'
            restrict_iots_dbver:
                aliases: ['restrict-iots-dbver']
                type: str
                description: Restrict system update to indicated file query database version
            stat_log:
                aliases: ['stat-log']
                type: str
                description:
                    - stat log setting
                    - emergency - The unit is unusable
                    - alert - Immediate action is required
                    - critical - Functionality is affected
                    - error - Functionality is probably affected
                    - warn - Functionality might be affected
                    - notice - Information about normal events
                    - info - General information
                    - debug - Debug information
                    - disable - Linkd logging is disabled.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warn'
                    - 'notice'
                    - 'info'
                    - 'debug'
                    - 'disable'
            iotv_preload:
                aliases: ['iotv-preload']
                type: str
                description:
                    - Enable/disable preloading IoT-Vulnerability database to memory
                    - disable - Disable IoT-Vulnerability db preload.
                    - enable - Enable IoT-Vulnerability db preload.
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
    - name: Configure the FortiGuard run parameters.
      fortinet.fortimanager.fmgr_fmupdate_webspam_fgdsetting:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        fmupdate_webspam_fgdsetting:
          # as_cache: <integer>
          # as_log: <value in [disable, nospam, all]>
          # as_preload: <value in [disable, enable]>
          # av_cache: <integer>
          # av_log: <value in [disable, novirus, all]>
          # av_preload: <value in [disable, enable]>
          # av2_cache: <integer>
          # av2_log: <value in [disable, noav2, all]>
          # av2_preload: <value in [disable, enable]>
          # eventlog_query: <value in [disable, enable]>
          # fgd_pull_interval: <integer>
          # fq_cache: <integer>
          # fq_log: <value in [disable, nofilequery, all]>
          # fq_preload: <value in [disable, enable]>
          # linkd_log: <value in [emergency, alert, critical, ...]>
          # max_client_worker: <integer>
          # max_log_quota: <integer>
          # max_unrated_site: <integer>
          # restrict_as1_dbver: <string>
          # restrict_as2_dbver: <string>
          # restrict_as4_dbver: <string>
          # restrict_av_dbver: <string>
          # restrict_av2_dbver: <string>
          # restrict_fq_dbver: <string>
          # restrict_wf_dbver: <string>
          # server_override:
          #   servlist:
          #     - id: <integer>
          #       ip: <string>
          #       ip6: <string>
          #       port: <integer>
          #       service_type: # <list or string>
          #         - "fgd"
          #         - "fgc"
          #         - "fsa"
          #         - "fgfq"
          #         - "geoip"
          #         - "iot-collect"
          #   status: <value in [disable, enable]>
          # stat_log_interval: <integer>
          # stat_sync_interval: <integer>
          # update_interval: <integer>
          # update_log: <value in [disable, enable]>
          # wf_cache: <integer>
          # wf_dn_cache_expire_time: <integer>
          # wf_dn_cache_max_number: <integer>
          # wf_log: <value in [disable, nourl, all]>
          # wf_preload: <value in [disable, enable]>
          # iot_cache: <integer>
          # iot_log: <value in [disable, nofilequery, all, ...]>
          # iot_preload: <value in [disable, enable]>
          # restrict_iots_dbver: <string>
          # stat_log: <value in [emergency, alert, critical, ...]>
          # iotv_preload: <value in [disable, enable]>
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
        '/cli/global/fmupdate/web-spam/fgd-setting'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'fmupdate_webspam_fgdsetting': {
            'type': 'dict',
            'v_range': [['6.0.0', '7.6.2']],
            'options': {
                'as-cache': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'as-log': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'nospam', 'all'], 'type': 'str'},
                'as-preload': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'av-cache': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'av-log': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'novirus', 'all'], 'type': 'str'},
                'av-preload': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'av2-cache': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'av2-log': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'noav2', 'all'], 'type': 'str'},
                'av2-preload': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'eventlog-query': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fgd-pull-interval': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'fq-cache': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'fq-log': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'nofilequery', 'all'], 'type': 'str'},
                'fq-preload': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'linkd-log': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable'],
                    'type': 'str'
                },
                'max-client-worker': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'max-log-quota': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'max-unrated-site': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'restrict-as1-dbver': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'restrict-as2-dbver': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'restrict-as4-dbver': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'restrict-av-dbver': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'restrict-av2-dbver': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'restrict-fq-dbver': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'restrict-wf-dbver': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                'server-override': {
                    'v_range': [['6.0.0', '7.6.2']],
                    'type': 'dict',
                    'options': {
                        'servlist': {
                            'v_range': [['6.0.0', '7.6.2']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                                'ip': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                                'ip6': {'v_range': [['6.0.0', '7.6.2']], 'type': 'str'},
                                'port': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                                'service-type': {
                                    'v_range': [['6.0.0', '7.6.2']],
                                    'type': 'raw',
                                    'choices': ['fgd', 'fgc', 'fsa', 'fgfq', 'geoip', 'iot-collect']
                                }
                            },
                            'elements': 'dict'
                        },
                        'status': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'stat-log-interval': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'stat-sync-interval': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'update-interval': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'update-log': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wf-cache': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'wf-dn-cache-expire-time': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'wf-dn-cache-max-number': {'v_range': [['6.0.0', '7.6.2']], 'type': 'int'},
                'wf-log': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'nourl', 'all'], 'type': 'str'},
                'wf-preload': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'iot-cache': {'v_range': [['6.4.6', '6.4.15'], ['7.0.1', '7.6.2']], 'type': 'int'},
                'iot-log': {'v_range': [['6.4.6', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['disable', 'nofilequery', 'all', 'noiot'], 'type': 'str'},
                'iot-preload': {'v_range': [['6.4.6', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'restrict-iots-dbver': {'v_range': [['6.4.6', '6.4.15'], ['7.0.1', '7.6.2']], 'type': 'str'},
                'stat-log': {
                    'v_range': [['7.0.10', '7.0.14'], ['7.2.5', '7.2.11'], ['7.4.2', '7.6.2']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warn', 'notice', 'info', 'debug', 'disable'],
                    'type': 'str'
                },
                'iotv-preload': {'v_range': [['7.2.2', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmupdate_webspam_fgdsetting'),
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
