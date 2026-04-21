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
module: fmgr_devprof_log_syslogd_filter
short_description: Filters for remote system server.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_log_syslogd_filter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            severity:
                type: str
                description: Lowest severity level to log.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            anomaly:
                type: str
                description: Enable/disable anomaly logging.
                choices:
                    - 'disable'
                    - 'enable'
            exclude_list:
                aliases: ['exclude-list']
                type: list
                elements: dict
                description: Exclude list.
                suboptions:
                    category:
                        type: str
                        description: Category.
                        choices:
                            - 'app-ctrl'
                            - 'attack'
                            - 'dlp'
                            - 'event'
                            - 'traffic'
                            - 'virus'
                            - 'voip'
                            - 'webfilter'
                            - 'netscan'
                            - 'spam'
                            - 'anomaly'
                            - 'waf'
                    fields:
                        type: list
                        elements: dict
                        description: Fields.
                        suboptions:
                            args:
                                type: raw
                                description: (list) Args.
                            field:
                                type: str
                                description: Field.
                            negate:
                                type: str
                                description: Negate.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    id:
                        type: int
                        description: Id.
            forward_traffic:
                aliases: ['forward-traffic']
                type: str
                description: Enable/disable forward traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            free_style:
                aliases: ['free-style']
                type: list
                elements: dict
                description: Free style.
                suboptions:
                    category:
                        type: str
                        description: Log category.
                        choices:
                            - 'traffic'
                            - 'event'
                            - 'virus'
                            - 'webfilter'
                            - 'attack'
                            - 'spam'
                            - 'voip'
                            - 'dlp'
                            - 'app-ctrl'
                            - 'anomaly'
                            - 'waf'
                            - 'gtp'
                            - 'dns'
                            - 'ssh'
                            - 'ssl'
                            - 'file-filter'
                            - 'icap'
                            - 'ztna'
                            - 'virtual-patch'
                            - 'debug'
                    filter:
                        type: str
                        description: Free style filter string.
                    filter_type:
                        aliases: ['filter-type']
                        type: str
                        description: Include/exclude logs that match the filter.
                        choices:
                            - 'include'
                            - 'exclude'
                    id:
                        type: int
                        description: Entry ID.
            gtp:
                type: str
                description: Enable/disable GTP messages logging.
                choices:
                    - 'disable'
                    - 'enable'
            local_traffic:
                aliases: ['local-traffic']
                type: str
                description: Enable/disable local in or out traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            multicast_traffic:
                aliases: ['multicast-traffic']
                type: str
                description: Enable/disable multicast traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            sniffer_traffic:
                aliases: ['sniffer-traffic']
                type: str
                description: Enable/disable sniffer traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            voip:
                type: str
                description: Enable/disable VoIP logging.
                choices:
                    - 'disable'
                    - 'enable'
            ztna_traffic:
                aliases: ['ztna-traffic']
                type: str
                description: Enable/disable ztna traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            filter_type:
                aliases: ['filter-type']
                type: str
                description: Include/exclude logs that match the filter.
                choices:
                    - 'include'
                    - 'exclude'
            filter:
                type: str
                description: Syslog filter.
            cifs:
                type: str
                description: Cifs.
                choices:
                    - 'disable'
                    - 'enable'
            ssl:
                type: str
                description: Ssl.
                choices:
                    - 'disable'
                    - 'enable'
            dns:
                type: str
                description: Enable/disable detailed DNS event logging.
                choices:
                    - 'disable'
                    - 'enable'
            ssh:
                type: str
                description: Enable/disable SSH logging.
                choices:
                    - 'disable'
                    - 'enable'
            netscan_discovery:
                aliases: ['netscan-discovery']
                type: str
                description: Enable/disable netscan discovery event logging.
                choices:
                    - 'disable'
                    - 'enable'
            netscan_vulnerability:
                aliases: ['netscan-vulnerability']
                type: str
                description: Enable/disable netscan vulnerability event logging.
                choices:
                    - 'disable'
                    - 'enable'
            forti_switch:
                aliases: ['forti-switch']
                type: str
                description: Enable/disable Forti-Switch logging.
                choices:
                    - 'disable'
                    - 'enable'
            http_transaction:
                aliases: ['http-transaction']
                type: str
                description: Enable/disable log HTTP transaction messages.
                choices:
                    - 'disable'
                    - 'enable'
            debug:
                type: str
                description: Enable/disable debug logging.
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
    - name: Filters for remote system server.
      fortinet.fortimanager.fmgr_devprof_log_syslogd_filter:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        devprof: <your own value>
        devprof_log_syslogd_filter:
          # severity: <value in [emergency, alert, critical, ...]>
          # anomaly: <value in [disable, enable]>
          # exclude_list:
          #   - category: <value in [app-ctrl, attack, dlp, ...]>
          #     fields:
          #       - args: <list or string>
          #         field: <string>
          #         negate: <value in [disable, enable]>
          #     id: <integer>
          # forward_traffic: <value in [disable, enable]>
          # free_style:
          #   - category: <value in [traffic, event, virus, ...]>
          #     filter: <string>
          #     filter_type: <value in [include, exclude]>
          #     id: <integer>
          # gtp: <value in [disable, enable]>
          # local_traffic: <value in [disable, enable]>
          # multicast_traffic: <value in [disable, enable]>
          # sniffer_traffic: <value in [disable, enable]>
          # voip: <value in [disable, enable]>
          # ztna_traffic: <value in [disable, enable]>
          # filter_type: <value in [include, exclude]>
          # filter: <string>
          # cifs: <value in [disable, enable]>
          # ssl: <value in [disable, enable]>
          # dns: <value in [disable, enable]>
          # ssh: <value in [disable, enable]>
          # netscan_discovery: <value in [disable, enable]>
          # netscan_vulnerability: <value in [disable, enable]>
          # forti_switch: <value in [disable, enable]>
          # http_transaction: <value in [disable, enable]>
          # debug: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter'
    ]
    url_params = ['adom', 'devprof']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_log_syslogd_filter': {
            'type': 'dict',
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
            'options': {
                'severity': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'anomaly': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'exclude-list': {
                    'v_range': [['7.0.4', '7.0.14']],
                    'type': 'list',
                    'options': {
                        'category': {
                            'v_range': [['7.0.4', '7.0.14']],
                            'choices': [
                                'app-ctrl', 'attack', 'dlp', 'event', 'traffic', 'virus', 'voip', 'webfilter', 'netscan', 'spam', 'anomaly', 'waf'
                            ],
                            'type': 'str'
                        },
                        'fields': {
                            'v_range': [['7.0.4', '7.0.14']],
                            'type': 'list',
                            'options': {
                                'args': {'v_range': [['7.0.4', '7.0.14']], 'type': 'raw'},
                                'field': {'v_range': [['7.0.4', '7.0.14']], 'type': 'str'},
                                'negate': {'v_range': [['7.0.4', '7.0.14']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'id': {'v_range': [['7.0.4', '7.0.14']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'forward-traffic': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'free-style': {
                    'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']],
                    'type': 'list',
                    'options': {
                        'category': {
                            'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']],
                            'choices': [
                                'traffic', 'event', 'virus', 'webfilter', 'attack', 'spam', 'voip', 'dlp', 'app-ctrl', 'anomaly', 'waf', 'gtp', 'dns',
                                'ssh', 'ssl', 'file-filter', 'icap', 'ztna', 'virtual-patch', 'debug'
                            ],
                            'type': 'str'
                        },
                        'filter': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                        'filter-type': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                        'id': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'gtp': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-traffic': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'multicast-traffic': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sniffer-traffic': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'voip': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ztna-traffic': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'filter-type': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                'filter': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'type': 'str'},
                'cifs': {'v_range': [['7.0.4', '7.0.14']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl': {'v_range': [['7.0.4', '7.0.14']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dns': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'netscan-discovery': {'v_range': [['7.0.4', '7.0.14']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'netscan-vulnerability': {'v_range': [['7.0.4', '7.0.14']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forti-switch': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-transaction': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'debug': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_log_syslogd_filter'),
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
