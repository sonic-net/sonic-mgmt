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
module: fmgr_system_sql
short_description: SQL settings.
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
    system_sql:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            background_rebuild:
                aliases: ['background-rebuild']
                type: str
                description:
                    - Disable/Enable rebuild SQL database in the background.
                    - disable - Rebuild SQL database not in the background.
                    - enable - Rebuild SQL database in the background.
                choices:
                    - 'disable'
                    - 'enable'
            custom_index:
                aliases: ['custom-index']
                type: list
                elements: dict
                description: Custom index.
                suboptions:
                    case_sensitive:
                        aliases: ['case-sensitive']
                        type: str
                        description:
                            - Disable/Enable case sensitive index.
                            - disable - Build a case insensitive index.
                            - enable - Build a case sensitive index.
                        choices:
                            - 'disable'
                            - 'enable'
                    device_type:
                        aliases: ['device-type']
                        type: str
                        description:
                            - Device type.
                            - FortiGate - Device type to FortiGate.
                            - FortiManager - Set device type to FortiManager
                            - FortiClient - Set device type to FortiClient
                            - FortiMail - Device type to FortiMail.
                            - FortiWeb - Device type to FortiWeb.
                            - FortiCache - Set device type to FortiCache
                            - FortiSandbox - Set device type to FortiSandbox
                            - FortiDDoS - Set device type to FortiDDoS
                            - FortiAuthenticator - Set device type to FortiAuthenticator
                            - FortiProxy - Set device type to FortiProxy
                        choices:
                            - 'FortiGate'
                            - 'FortiManager'
                            - 'FortiClient'
                            - 'FortiMail'
                            - 'FortiWeb'
                            - 'FortiCache'
                            - 'FortiSandbox'
                            - 'FortiDDoS'
                            - 'FortiAuthenticator'
                            - 'FortiProxy'
                    id:
                        type: int
                        description: Add or Edit log index fields.
                    index_field:
                        aliases: ['index-field']
                        type: str
                        description: Log field name to be indexed.
                    log_type:
                        aliases: ['log-type']
                        type: str
                        description:
                            - Log type.
                            - none - none
                            - app-ctrl
                            - attack
                            - content
                            - dlp
                            - emailfilter
                            - event
                            - generic
                            - history
                            - traffic
                            - virus
                            - voip
                            - webfilter
                            - netscan
                            - fct-event
                            - fct-traffic
                            - fct-netscan
                            - waf
                            - gtp
                            - dns
                            - ssh
                            - ssl
                        choices:
                            - 'none'
                            - 'app-ctrl'
                            - 'attack'
                            - 'content'
                            - 'dlp'
                            - 'emailfilter'
                            - 'event'
                            - 'generic'
                            - 'history'
                            - 'traffic'
                            - 'virus'
                            - 'voip'
                            - 'webfilter'
                            - 'netscan'
                            - 'fct-event'
                            - 'fct-traffic'
                            - 'fct-netscan'
                            - 'waf'
                            - 'gtp'
                            - 'dns'
                            - 'ssh'
                            - 'ssl'
                            - 'file-filter'
                            - 'asset'
                            - 'protocol'
                            - 'siem'
                            - 'ztna'
                            - 'security'
            database_name:
                aliases: ['database-name']
                type: str
                description: Database name.
            database_type:
                aliases: ['database-type']
                type: str
                description:
                    - Database type.
                    - mysql - MySQL database.
                    - postgres - PostgreSQL local database.
                choices:
                    - 'mysql'
                    - 'postgres'
            device_count_high:
                aliases: ['device-count-high']
                type: str
                description:
                    - Must set to enable if the count of registered devices is greater than 8000.
                    - disable - Set to disable if device count is less than 8000.
                    - enable - Set to enable if device count is equal to or greater than 8000.
                choices:
                    - 'disable'
                    - 'enable'
            event_table_partition_time:
                aliases: ['event-table-partition-time']
                type: int
                description: Maximum SQL database table partitioning time range in minute
            fct_table_partition_time:
                aliases: ['fct-table-partition-time']
                type: int
                description: Maximum SQL database table partitioning time range in minute
            logtype:
                type: list
                elements: str
                description:
                    - Log type.
                    - none - None.
                    - app-ctrl
                    - attack
                    - content
                    - dlp
                    - emailfilter
                    - event
                    - generic
                    - history
                    - traffic
                    - virus
                    - voip
                    - webfilter
                    - netscan
                    - fct-event
                    - fct-traffic
                    - fct-netscan
                    - waf
                    - gtp
                    - dns
                    - ssh
                    - ssl
                choices:
                    - 'none'
                    - 'app-ctrl'
                    - 'attack'
                    - 'content'
                    - 'dlp'
                    - 'emailfilter'
                    - 'event'
                    - 'generic'
                    - 'history'
                    - 'traffic'
                    - 'virus'
                    - 'voip'
                    - 'webfilter'
                    - 'netscan'
                    - 'fct-event'
                    - 'fct-traffic'
                    - 'fct-netscan'
                    - 'waf'
                    - 'gtp'
                    - 'dns'
                    - 'ssh'
                    - 'ssl'
                    - 'file-filter'
                    - 'asset'
                    - 'protocol'
                    - 'siem'
                    - 'ztna'
                    - 'security'
            password:
                type: raw
                description: (list) Password for login remote database.
            prompt_sql_upgrade:
                aliases: ['prompt-sql-upgrade']
                type: str
                description:
                    - Prompt to convert log database into SQL database at start time on GUI.
                    - disable - Do not prompt to upgrade log database to SQL database at start time on GUI.
                    - enable - Prompt to upgrade log database to SQL database at start time on GUI.
                choices:
                    - 'disable'
                    - 'enable'
            rebuild_event:
                aliases: ['rebuild-event']
                type: str
                description:
                    - Disable/Enable rebuild event during SQL database rebuilding.
                    - disable - Do not rebuild event during SQL database rebuilding.
                    - enable - Rebuild event during SQL database rebuilding.
                choices:
                    - 'disable'
                    - 'enable'
            rebuild_event_start_time:
                aliases: ['rebuild-event-start-time']
                type: raw
                description: (list) Rebuild event starting date and time
            server:
                type: str
                description: Database IP or hostname.
            start_time:
                aliases: ['start-time']
                type: raw
                description: (list) Start date and time
            status:
                type: str
                description:
                    - SQL database status.
                    - disable - Disable SQL database.
                    - local - Enable local database.
                choices:
                    - 'disable'
                    - 'local'
            text_search_index:
                aliases: ['text-search-index']
                type: str
                description:
                    - Disable/Enable text search index.
                    - disable - Do not create text search index.
                    - enable - Create text search index.
                choices:
                    - 'disable'
                    - 'enable'
            traffic_table_partition_time:
                aliases: ['traffic-table-partition-time']
                type: int
                description: Maximum SQL database table partitioning time range in minute
            ts_index_field:
                aliases: ['ts-index-field']
                type: list
                elements: dict
                description: Ts index field.
                suboptions:
                    category:
                        type: str
                        description: Category of text search index fields.
                    value:
                        type: str
                        description: Fields of text search index.
            username:
                type: str
                description: User name for login remote database.
            utm_table_partition_time:
                aliases: ['utm-table-partition-time']
                type: int
                description: Maximum SQL database table partitioning time range in minute
            custom_skipidx:
                aliases: ['custom-skipidx']
                type: list
                elements: dict
                description: Custom skipidx.
                suboptions:
                    device_type:
                        aliases: ['device-type']
                        type: str
                        description:
                            - Device type.
                            - FortiGate - Set device type to FortiGate.
                            - FortiManager - Set device type to FortiManager
                            - FortiClient - Set device type to FortiClient.
                            - FortiMail - Set device type to FortiMail.
                            - FortiWeb - Set device type to FortiWeb.
                            - FortiSandbox - Set device type to FortiSandbox
                            - FortiProxy - Set device type to FortiProxy
                        choices:
                            - 'FortiGate'
                            - 'FortiManager'
                            - 'FortiClient'
                            - 'FortiMail'
                            - 'FortiWeb'
                            - 'FortiSandbox'
                            - 'FortiProxy'
                    id:
                        type: int
                        description: Add or Edit log index fields.
                    index_field:
                        aliases: ['index-field']
                        type: str
                        description: Field to be added to skip index.
                    log_type:
                        aliases: ['log-type']
                        type: str
                        description:
                            - Log type.
                            - app-ctrl
                            - attack
                            - content
                            - dlp
                            - emailfilter
                            - event
                            - generic
                            - history
                            - traffic
                            - virus
                            - voip
                            - webfilter
                            - netscan
                            - fct-event
                            - fct-traffic
                            - fct-netscan
                            - waf
                            - gtp
                            - dns
                            - ssh
                            - ssl
                            - file-filter
                            - asset
                        choices:
                            - 'app-ctrl'
                            - 'attack'
                            - 'content'
                            - 'dlp'
                            - 'emailfilter'
                            - 'event'
                            - 'generic'
                            - 'history'
                            - 'traffic'
                            - 'virus'
                            - 'voip'
                            - 'webfilter'
                            - 'netscan'
                            - 'fct-event'
                            - 'fct-traffic'
                            - 'fct-netscan'
                            - 'waf'
                            - 'gtp'
                            - 'dns'
                            - 'ssh'
                            - 'ssl'
                            - 'file-filter'
                            - 'asset'
                            - 'protocol'
                            - 'siem'
                            - 'ztna'
                            - 'security'
            compress_table_min_age:
                aliases: ['compress-table-min-age']
                type: int
                description: Minimum age in days for SQL tables to be compressed.
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
    - name: SQL settings.
      fortinet.fortimanager.fmgr_system_sql:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        system_sql:
          # background_rebuild: <value in [disable, enable]>
          # custom_index:
          #   - case_sensitive: <value in [disable, enable]>
          #     device_type: <value in [FortiGate, FortiManager, FortiClient, ...]>
          #     id: <integer>
          #     index_field: <string>
          #     log_type: <value in [none, app-ctrl, attack, ...]>
          # database_name: <string>
          # database_type: <value in [mysql, postgres]>
          # device_count_high: <value in [disable, enable]>
          # event_table_partition_time: <integer>
          # fct_table_partition_time: <integer>
          # logtype:
          #   - "none"
          #   - "app-ctrl"
          #   - "attack"
          #   - "content"
          #   - "dlp"
          #   - "emailfilter"
          #   - "event"
          #   - "generic"
          #   - "history"
          #   - "traffic"
          #   - "virus"
          #   - "voip"
          #   - "webfilter"
          #   - "netscan"
          #   - "fct-event"
          #   - "fct-traffic"
          #   - "fct-netscan"
          #   - "waf"
          #   - "gtp"
          #   - "dns"
          #   - "ssh"
          #   - "ssl"
          #   - "file-filter"
          #   - "asset"
          #   - "protocol"
          #   - "siem"
          #   - "ztna"
          #   - "security"
          # password: <list or string>
          # prompt_sql_upgrade: <value in [disable, enable]>
          # rebuild_event: <value in [disable, enable]>
          # rebuild_event_start_time: <list or string>
          # server: <string>
          # start_time: <list or string>
          # status: <value in [disable, local]>
          # text_search_index: <value in [disable, enable]>
          # traffic_table_partition_time: <integer>
          # ts_index_field:
          #   - category: <string>
          #     value: <string>
          # username: <string>
          # utm_table_partition_time: <integer>
          # custom_skipidx:
          #   - device_type: <value in [FortiGate, FortiManager, FortiClient, ...]>
          #     id: <integer>
          #     index_field: <string>
          #     log_type: <value in [app-ctrl, attack, content, ...]>
          # compress_table_min_age: <integer>
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
        '/cli/global/system/sql'
    ]
    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'system_sql': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'background-rebuild': {'choices': ['disable', 'enable'], 'type': 'str'},
                'custom-index': {
                    'type': 'list',
                    'options': {
                        'case-sensitive': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'device-type': {
                            'choices': [
                                'FortiGate', 'FortiManager', 'FortiClient', 'FortiMail', 'FortiWeb', 'FortiCache', 'FortiSandbox', 'FortiDDoS',
                                'FortiAuthenticator', 'FortiProxy'
                            ],
                            'type': 'str'
                        },
                        'id': {'type': 'int'},
                        'index-field': {'type': 'str'},
                        'log-type': {
                            'choices': [
                                'none', 'app-ctrl', 'attack', 'content', 'dlp', 'emailfilter', 'event', 'generic', 'history', 'traffic', 'virus', 'voip',
                                'webfilter', 'netscan', 'fct-event', 'fct-traffic', 'fct-netscan', 'waf', 'gtp', 'dns', 'ssh', 'ssl', 'file-filter',
                                'asset', 'protocol', 'siem', 'ztna', 'security'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'database-name': {'type': 'str'},
                'database-type': {'choices': ['mysql', 'postgres'], 'type': 'str'},
                'device-count-high': {'choices': ['disable', 'enable'], 'type': 'str'},
                'event-table-partition-time': {'type': 'int'},
                'fct-table-partition-time': {'type': 'int'},
                'logtype': {
                    'type': 'list',
                    'choices': [
                        'none', 'app-ctrl', 'attack', 'content', 'dlp', 'emailfilter', 'event', 'generic', 'history', 'traffic', 'virus', 'voip',
                        'webfilter', 'netscan', 'fct-event', 'fct-traffic', 'fct-netscan', 'waf', 'gtp', 'dns', 'ssh', 'ssl', 'file-filter', 'asset',
                        'protocol', 'siem', 'ztna', 'security'
                    ],
                    'elements': 'str'
                },
                'password': {'no_log': True, 'type': 'raw'},
                'prompt-sql-upgrade': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rebuild-event': {'v_range': [['6.0.0', '7.4.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rebuild-event-start-time': {'v_range': [['6.0.0', '7.4.0']], 'type': 'raw'},
                'server': {'type': 'str'},
                'start-time': {'type': 'raw'},
                'status': {'choices': ['disable', 'local'], 'type': 'str'},
                'text-search-index': {'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-table-partition-time': {'type': 'int'},
                'ts-index-field': {'type': 'list', 'options': {'category': {'type': 'str'}, 'value': {'type': 'str'}}, 'elements': 'dict'},
                'username': {'type': 'str'},
                'utm-table-partition-time': {'type': 'int'},
                'custom-skipidx': {
                    'v_range': [['6.2.3', '']],
                    'type': 'list',
                    'options': {
                        'device-type': {
                            'v_range': [['6.2.3', '']],
                            'choices': ['FortiGate', 'FortiManager', 'FortiClient', 'FortiMail', 'FortiWeb', 'FortiSandbox', 'FortiProxy'],
                            'type': 'str'
                        },
                        'id': {'v_range': [['6.2.3', '']], 'type': 'int'},
                        'index-field': {'v_range': [['6.2.3', '']], 'type': 'str'},
                        'log-type': {
                            'v_range': [['6.2.3', '']],
                            'choices': [
                                'app-ctrl', 'attack', 'content', 'dlp', 'emailfilter', 'event', 'generic', 'history', 'traffic', 'virus', 'voip',
                                'webfilter', 'netscan', 'fct-event', 'fct-traffic', 'fct-netscan', 'waf', 'gtp', 'dns', 'ssh', 'ssl', 'file-filter',
                                'asset', 'protocol', 'siem', 'ztna', 'security'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'compress-table-min-age': {'v_range': [['6.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sql'),
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
